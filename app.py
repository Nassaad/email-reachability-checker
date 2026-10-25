import io
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import pandas as pd
import streamlit as st
from email_validator import EmailNotValidError, validate_email

st.set_page_config(page_title="Email Reachability Checker", page_icon="✉️", layout="wide")

st.title("✉️ Email Reachability Checker")
st.caption("Syntax • DNS/MX • SMTP signals • Catch-all • Disposable domains")

st.warning(
    "SMTP recipient checks are inherently inconclusive. Many providers block port 25, "
    "hide mailbox existence, defer rejection, or accept every recipient. This tool does not "
    "send email and cannot guarantee inbox delivery. Use only with addresses you are authorized to assess."
)

DEFAULT_TIMEOUT = 5.0
MAX_WORKERS = 8
MAX_ROWS = 5000

# Small starter list. Expand this list from a reputable, maintained source for production use.
DISPOSABLE_DOMAINS = {
    "10minutemail.com", "10minutemail.net", "guerrillamail.com", "guerrillamail.net",
    "mailinator.com", "yopmail.com", "temp-mail.org", "tempmail.com",
    "throwawaymail.com", "getnada.com", "fakeinbox.com", "dispostable.com",
    "maildrop.cc", "trashmail.com", "mintemail.com", "sharklasers.com",
}

def resolver_for(timeout: float):
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    return r

def lookup_dns(domain: str, timeout: float):
    """Return MX and A/AAAA fallback findings; DNS errors are represented, not raised."""
    r = resolver_for(timeout)
    mx_hosts = []
    mx_status = "unknown"
    domain_ip_status = "unknown"
    notes = []

    try:
        answers = r.resolve(domain, "MX")
        records = sorted(
            [(int(a.preference), str(a.exchange).rstrip(".")) for a in answers],
            key=lambda x: x[0],
        )
        # RFC 7505 null MX means the domain explicitly does not accept email.
        if len(records) == 1 and records[0][1] == "":
            mx_status = "null_mx"
            notes.append("Domain publishes Null MX (does not accept email).")
        else:
            mx_hosts = [host for _, host in records if host]
            mx_status = "found" if mx_hosts else "not_found"
    except dns.resolver.NoAnswer:
        mx_status = "not_found"
        notes.append("No MX record; checking address records as fallback.")
    except dns.resolver.NXDOMAIN:
        mx_status = "domain_not_found"
        notes.append("Domain does not exist (NXDOMAIN).")
        return mx_status, mx_hosts, "not_checked", notes
    except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.LifetimeTimeout) as e:
        mx_status = "dns_error"
        notes.append(f"MX lookup inconclusive: {type(e).__name__}.")

    if mx_status == "null_mx":
        return mx_status, mx_hosts, "not_checked", notes

    try:
        a_records = list(r.resolve(domain, "A"))
        domain_ip_status = "found" if a_records else "not_found"
    except dns.resolver.NXDOMAIN:
        domain_ip_status = "domain_not_found"
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.resolver.LifetimeTimeout):
        try:
            aaaa_records = list(r.resolve(domain, "AAAA"))
            domain_ip_status = "found" if aaaa_records else "not_found"
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            domain_ip_status = "not_found"

    # If no MX but domain has A/AAAA, SMTP can be routed to the address domain per fallback rules.
    if mx_status == "not_found" and domain_ip_status == "found":
        notes.append("No MX record, but domain has an address record; implicit-MX fallback may apply.")
    return mx_status, mx_hosts, domain_ip_status, notes

def smtp_probe(domain: str, mx_hosts: list[str], email: str, timeout: float):
    """
    Minimal SMTP conversation: connect, EHLO, MAIL FROM, RCPT TO, QUIT.
    No message body is sent. Recipient replies are signals only, not proof.
    """
    hosts = mx_hosts[:3] if mx_hosts else [domain]
    attempts = []
    for host in hosts:
        sock = None
        try:
            sock = socket.create_connection((host, 25), timeout=timeout)
            sock.settimeout(timeout)
            f = sock.makefile("rwb", buffering=0)

            def read_response():
                lines = []
                while True:
                    line = f.readline(2048)
                    if not line:
                        raise TimeoutError("SMTP connection closed before response")
                    decoded = line.decode("utf-8", errors="replace").rstrip("\r\n")
                    lines.append(decoded)
                    # SMTP multiline response: continuation has '-' after status code.
                    if len(decoded) < 4 or decoded[3] != "-":
                        break
                first = lines[0]
                try:
                    code = int(first[:3])
                except (ValueError, IndexError):
                    code = 0
                return code, " | ".join(lines)[:500]

            def command(cmd):
                f.write((cmd + "\r\n").encode("ascii", errors="ignore"))
                return read_response()

            code, banner = read_response()
            if code < 200 or code >= 400:
                attempts.append((host, "smtp_unavailable", f"Banner: {banner}"))
                continue
            ehlo_code, ehlo_msg = command("EHLO reachability-check.local")
            if ehlo_code >= 500:
                helo_code, helo_msg = command("HELO reachability-check.local")
                if helo_code >= 400:
                    attempts.append((host, "smtp_unavailable", f"EHLO/HELO rejected: {helo_msg}"))
                    continue

            # Null reverse-path avoids inventing or using a real sender identity.
            mail_code, mail_msg = command("MAIL FROM:<>")
            if mail_code >= 400:
                attempts.append((host, "smtp_unavailable", f"MAIL FROM rejected: {mail_msg}"))
                continue

            rcpt_code, rcpt_msg = command(f"RCPT TO:<{email}>")
            try:
                command("RSET")
                command("QUIT")
            except Exception:
                pass

            if 200 <= rcpt_code < 300:
                return "accepted", f"{host}: RCPT accepted ({rcpt_code}); mailbox existence is not confirmed."
            if 500 <= rcpt_code < 600:
                # Some servers give policy / anti-enumeration errors rather than mailbox-specific rejection.
                if rcpt_code in (550, 551, 553) and any(
                    word in rcpt_msg.lower()
                    for word in ("user unknown", "no such user", "mailbox unavailable",
                                 "recipient address rejected", "unknown recipient", "does not exist")
                ):
                    return "rejected", f"{host}: RCPT rejected ({rcpt_code}); server response may still be policy-based."
                return "inconclusive", f"{host}: RCPT rejected ({rcpt_code}); may be policy/anti-enumeration."
            return "inconclusive", f"{host}: unexpected RCPT response ({rcpt_code}): {rcpt_msg}"
        except (socket.timeout, TimeoutError):
            attempts.append((host, "smtp_timeout", "Connection or SMTP response timed out."))
        except OSError:
            attempts.append((host, "smtp_unavailable", "Connection failed or SMTP port 25 is blocked."))
        except Exception as e:
            attempts.append((host, "smtp_error", f"{type(e).__name__}: {str(e)[:160]}"))
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    if not attempts:
        return "not_attempted", "No mail server host available for SMTP probe."
    # Prefer a timeout if every attempt failed by timeout; otherwise summarize.
    statuses = {a[1] for a in attempts}
    details = "; ".join(f"{h}: {msg}" for h, _, msg in attempts)
    if statuses == {"smtp_timeout"}:
        return "timeout", details
    return "unavailable", details

def ssl_error_types():
    # Kept as a tuple helper so exception handling remains explicit and portable.
    return (ConnectionError,)

def verify_email(raw_email: str, timeout: float, do_smtp: bool, detect_catchall: bool):
    result = {
        "email_input": raw_email,
        "email": "",
        "syntax_status": "invalid",
        "domain": "",
        "mx_status": "not_checked",
        "mx_hosts": "",
        "domain_ip_status": "not_checked",
        "disposable": False,
        "smtp_status": "not_attempted",
        "catch_all": "not_checked",
        "overall_status": "unknown",
        "details": "",
        "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        v = validate_email(str(raw_email).strip(), check_deliverability=False)
        email = v.normalized
        domain = v.domain.lower()
        result.update(email=email, syntax_status="valid", domain=domain)
    except (EmailNotValidError, ValueError, TypeError) as e:
        result["details"] = f"Syntax validation failed: {str(e)[:240]}"
        result["overall_status"] = "invalid"
        return result

    result["disposable"] = domain in DISPOSABLE_DOMAINS
    mx_status, mx_hosts, ip_status, dns_notes = lookup_dns(domain, timeout)
    result.update(
        mx_status=mx_status,
        mx_hosts=", ".join(mx_hosts),
        domain_ip_status=ip_status,
    )
    notes = list(dns_notes)

    if mx_status in ("domain_not_found", "null_mx") or (
        mx_status == "not_found" and ip_status != "found"
    ):
        result["overall_status"] = "undeliverable_domain"
        result["smtp_status"] = "not_attempted"
        notes.append("Mail routing is not available based on current DNS findings.")
        result["details"] = " ".join(notes)
        if result["disposable"]:
            result["details"] += " Domain is also on the built-in disposable-domain list."
        return result

    if do_smtp and (mx_hosts or ip_status == "found"):
        smtp_status, smtp_details = smtp_probe(domain, mx_hosts, email, timeout)
        result["smtp_status"] = smtp_status
        notes.append(smtp_details)
    else:
        result["smtp_status"] = "not_attempted"
        notes.append("SMTP probe disabled or no usable mail host found.")

    if detect_catchall and do_smtp and (mx_hosts or ip_status == "found"):
        # Random recipient test is a heuristic, not a guarantee. Use a reserved-looking random local part.
        import secrets
        random_local = "reachcheck-" + secrets.token_hex(8)
        random_address = f"{random_local}@{domain}"
        catch_status, catch_details = smtp_probe(domain, mx_hosts, random_address, timeout)
        if catch_status == "accepted":
            result["catch_all"] = "likely"
            notes.append("Random test recipient was accepted; domain may be catch-all.")
        elif catch_status == "rejected":
            result["catch_all"] = "not_detected"
            notes.append("Random test recipient was rejected; catch-all not detected.")
        else:
            result["catch_all"] = "unknown"
            notes.append(f"Catch-all test inconclusive: {catch_details}")

    if result["disposable"]:
        result["overall_status"] = "risky_disposable"
    elif mx_status == "dns_error":
        result["overall_status"] = "unknown"
    elif result["smtp_status"] == "rejected" and result["catch_all"] != "likely":
        result["overall_status"] = "likely_undeliverable_mailbox"
    elif result["smtp_status"] == "accepted":
        result["overall_status"] = "smtp_accepted_not_verified"
    elif result["smtp_status"] in ("unavailable", "timeout", "inconclusive", "smtp_error"):
        result["overall_status"] = "unknown"
    else:
        result["overall_status"] = "domain_mail_routing_found"

    result["details"] = " ".join(notes)
    return result

with st.sidebar:
    st.header("Settings")
    timeout = st.slider("Timeout per SMTP/DNS operation (seconds)", 2.0, 12.0, DEFAULT_TIMEOUT, 1.0)
    do_smtp = st.checkbox("Attempt SMTP recipient checks (port 25)", value=True)
    detect_catchall = st.checkbox("Run catch-all heuristic (extra SMTP request)", value=True)
    workers = st.slider("Parallel checks", 1, 12, 4)
    st.caption("More workers can trigger provider rate limits. Keep concurrency modest.")
    st.caption("Built-in disposable list is illustrative and not comprehensive.")

tab_single, tab_bulk, tab_guide = st.tabs(["Single email", "Bulk check", "Status guide"])

def show_results(df: pd.DataFrame, key: str):
    if df.empty:
        st.info("No results to display.")
        return
    counts = df["overall_status"].value_counts()
    cols = st.columns(4)
    cols[0].metric("Checked", len(df))
    cols[1].metric("SMTP accepted*", int((df["smtp_status"] == "accepted").sum()))
    cols[2].metric("Likely invalid", int(df["overall_status"].isin(["invalid", "undeliverable_domain", "likely_undeliverable_mailbox"]).sum()))
    cols[3].metric("Unknown / inconclusive", int(df["overall_status"].isin(["unknown", "domain_mail_routing_found"]).sum()))
    st.caption("*SMTP acceptance is not proof of mailbox existence or inbox delivery.")
    st.dataframe(df, use_container_width=True, hide_index=True)
    csv_bytes = df.to_csv(index=False).encode("utf-8-sig")
    st.download_button(
        "Download results as CSV",
        data=csv_bytes,
        file_name=f"email_reachability_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        key=key,
    )

def run_checks(emails):
    # Trim, skip blank values, preserve order, and de-duplicate case-insensitively.
    cleaned = []
    seen = set()
    for item in emails:
        e = str(item).strip()
        if not e:
            continue
        k = e.casefold()
        if k not in seen:
            seen.add(k)
            cleaned.append(e)
    if len(cleaned) > MAX_ROWS:
        st.error(f"Maximum {MAX_ROWS:,} unique email addresses per run. Your input has {len(cleaned):,}.")
        return
    if not cleaned:
        st.warning("Enter or upload at least one email address.")
        return

    progress = st.progress(0, text="Preparing checks…")
    status_text = st.empty()
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(verify_email, e, timeout, do_smtp, detect_catchall): e
            for e in cleaned
        }
        for i, future in enumerate(as_completed(futures), start=1):
            email = futures[future]
            try:
                results.append(future.result())
            except Exception as e:
                results.append({
                    "email_input": email, "email": "", "syntax_status": "unknown",
                    "domain": "", "mx_status": "unknown", "mx_hosts": "",
                    "domain_ip_status": "unknown", "disposable": False,
                    "smtp_status": "error", "catch_all": "unknown",
                    "overall_status": "unknown",
                    "details": f"Unexpected checker error: {type(e).__name__}: {str(e)[:200]}",
                    "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                })
            progress.progress(i / len(cleaned), text=f"Checked {i:,} of {len(cleaned):,}")
            status_text.write(f"Latest completed: `{email}`")
    # Restore original unique input order for readable reports.
    order = {email: i for i, email in enumerate(cleaned)}
    results.sort(key=lambda row: order.get(row["email_input"], len(order)))
    df = pd.DataFrame(results)
    st.session_state["last_results"] = df
    progress.empty()
    status_text.empty()
    show_results(df, "download_results")

with tab_single:
    st.subheader("Check one email address")
    with st.form("single_form"):
        one_email = st.text_input("Email address", placeholder="person@example.com")
        submit_single = st.form_submit_button("Check email", type="primary")
    if submit_single:
        if not one_email.strip():
            st.error("Enter an email address.")
        else:
            run_checks([one_email])
    elif "last_results" in st.session_state:
        st.caption("Most recent check results")
        show_results(st.session_state["last_results"], "download_single_previous")

with tab_bulk:
    st.subheader("Bulk email checking")
    st.write("Upload a CSV or TXT file. For CSV, the app uses a column named `email` if available; otherwise it scans cells for email-like values.")
    uploaded = st.file_uploader("Upload CSV or TXT", type=["csv", "txt"])
    pasted = st.text_area("Or paste email addresses (one per line or separated by commas)", height=130)
    if st.button("Check bulk emails", type="primary"):
        emails = []
        if uploaded is not None:
            try:
                raw = uploaded.getvalue().decode("utf-8-sig", errors="replace")
                if uploaded.name.lower().endswith(".csv"):
                    data = pd.read_csv(io.StringIO(raw), dtype=str, keep_default_na=False)
                    email_col = next((c for c in data.columns if c.strip().lower() == "email"), None)
                    if email_col:
                        emails.extend(data[email_col].tolist())
                    else:
                        for col in data.columns:
                            emails.extend(data[col].tolist())
                else:
                    emails.extend(re.split(r"[\s,;]+", raw))
            except Exception as e:
                st.error(f"Could not read uploaded file: {e}")
        if pasted.strip():
            emails.extend(re.split(r"[\s,;]+", pasted))
        run_checks(emails)

with tab_guide:
    st.subheader("How to interpret statuses")
    guide = pd.DataFrame([
        ("invalid", "Email syntax failed; address was not checked further."),
        ("undeliverable_domain", "Domain does not exist, publishes Null MX, or has no apparent mail routing."),
        ("likely_undeliverable_mailbox", "SMTP server rejected the recipient with a mailbox-related response; policy responses can still mislead."),
        ("smtp_accepted_not_verified", "Server accepted RCPT TO. This does not prove the mailbox exists or that a message will reach inbox."),
        ("domain_mail_routing_found", "Mail routing exists, but mailbox-level verification was unavailable or not attempted."),
        ("risky_disposable", "Domain appears in the app's small built-in disposable list."),
        ("unknown", "DNS or SMTP behavior was inconclusive, blocked, timed out, or policy-restricted."),
    ], columns=["Status", "Meaning"])
    st.dataframe(guide, use_container_width=True, hide_index=True)
    st.markdown("""
**Operational notes**
- The app never sends an email body. It makes DNS lookups and, when enabled, SMTP handshake/recipient commands.
- Port 25 may be blocked on home networks, cloud hosts, or VPS providers. A timeout is reported as unknown, not invalid.
- Some mail providers accept all recipients or deliberately conceal mailbox existence. Catch-all detection is only a heuristic.
- Do not run large lists against third-party servers without authorization; use conservative concurrency.
- For high-volume production validation, consider a reputable email-verification API and review its privacy/data-retention terms.
""")
