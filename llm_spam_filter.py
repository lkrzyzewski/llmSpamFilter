#!/usr/local/aienv/bin/python3
import asyncio
import logging
import email
from email import policy
from email.parser import BytesParser
from email.message import Message
from typing import Optional
import json
import aiosmtplib
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message as AiosmtpdMessageHandler
from aiosmtpd.smtp import Envelope, Session, SMTP
import requests
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
# --- Configuration ---
LISTEN_HOST = 'localhost'
LISTEN_PORT = 10030
FORWARD_HOST = 'host.to.forward.com' # host name of mta server
FORWARD_PORT = 10029
AIHOST = "10.254.100.19:80" #host name or IP of AI server

logfilename = "/var/log/phishing_filter.log"
whitelistfilename = "/etc/phishing_filter/phishing_whitelist.txt"

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

#list of local domainst to exclude as a sender,  
local_domains = ["localdomain.com"]
#list o names used in Spear Phishing check. If thous names are used in pair with non local domain used in From header.
spearnames = ["Jon Doe"]

def spear_check(From, local_domains):
    from_domain = False
    for name in spearnames:
        if name in From:
            From = From.split(" ")
            for word in From:
                if "@" in word:
                    if word[:1] == "<" and word[-1:] == ">":
                        domain = word[1:-1]
                        domain = domain.split("@")[1]
                    else:
                        domain = word.split("@")[1]
                    if domain in local_domains:
                        from_domain = True
    return from_domain

def get_domain(mail_from):
    if "@" in mail_from:
        if mail_from[:1] == "<" and mail_from[-1:] == ">":
            domain = mail_from[1:-1]
            domain = domain.split("@")
            if domain[1] != '' :
                domain = domain[1]
            else:
                domain = domain[0]

        else:
            domain = mail_from.split("@")
            if domain[1] != '' :
                domain = domain[1]
            else:
                domain = domain[0]
    else:
        domain = mail_from
    return domain


def modify_subject(message: Message):
    log.info("Email marked as spear phishing. Modifying subject.")
    original_subject = message.get('Subject', '')
    new_subject = f"[SUSPICIOUS] {original_subject}"
    try:
        del message['Subject']
    except KeyError:
        pass
    message['Subject'] = new_subject
    log.info(f"New subject: {new_subject}")
    return message                
            

def add_header(message: Message):
    log.info("Email marked as spam. Adding header.")
    message.add_header('AIspam', 'Yes')
    #message['AISpam'] = 'True'
    return message

def add_spear_header(message: Message):
    log.info("Email marked as spearphishing. Adding header.")
    message.add_header('SpearPhishing', 'Yes')
    #message['AISpam'] = 'True'
    return message

# --- Classification function (placeholder) ---
def classify_email(message: Message) -> str:

    #mail = email.message_from_bytes(message, policy=policy.default)
    subject = message['Subject']
    body = extract_email_body_text_enhanced(message.as_bytes())
    if len(body) > 5000:
        body = body[:5000]
    log.info("Email text extracted")
    url = f"http://{AIHOST}/"
    headers = {"X-API-KEY": "ohTho6Oorele8oshoh3ooghaidi1Queewug4Ik8eixaebu4erooDahsh0Nah3quo"}
    classification = {"phishing_pred": "ok", "spam_pred": "ham"}
    data = {"subject": subject, "body": body}
    if len(body.strip()) > 25:
        try: 
            response = requests.post(url, headers=headers, json=data, timeout=(10, 20))
            if response.status_code == 200:
                
                classification = response.json()
                log.info(f"Classification successful: {classification}")
            else:
                log.info(f"Classification error: {response.status_code}")
        except Exception as e:
            log.info(f"Connection error: {e}")
        

    return classification

 

def extract_email_body_text_enhanced(email_data) -> Optional[str]:
    """
    Parses raw email data and extracts the content. Priority is 'text/plain'.
    If 'text/plain' is unavailable, it attempts to extract text from 'text/html',
    removing HTML tags. It ignores attachments.

    Requires the 'beautifulsoup4' library to process HTML content.

    Args:
        email_data: A string containing the raw email content (headers + body).

    Returns:
        A string with the extracted text content, or None if email parsing
        fails. Returns an empty string if no suitable text/plain or text/html content
        is found, or if BeautifulSoup4 is unavailable for HTML content.
    """
    # Quick check and warning if HTML is present and BS4 is missing
    # Checking 'content-type: text/html' is more reliable than just 'text/html'
    # in the body, but this simple check can catch many cases.
    if not BS4_AVAILABLE and 'content-type: text/html' in email_data.lower():
         log.debug("Warning: BeautifulSoup4 library not found (install: pip install beautifulsoup4).")
         log.debug("             HTML content cannot be processed.")
         # You can decide whether to return None, an empty string, or raise an error here.
         # For now, the function will continue, but it will not process HTML.

    try:
        # Parsing the email using the default policy
        msg: Message = email.message_from_bytes(email_data, policy=policy.default)
    except Exception as e:
        log.debug(f"Error while parsing email: {e}")
        return None

    plain_text_parts = []
    html_parts = [] # List to store raw HTML content

    # Walk through the email parts (if it's multipart)
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            # Safely get Content-Disposition and convert to lowercase
            content_disposition = part.get("Content-Disposition", "").lower()

            # Skip parts that are explicitly marked as attachments
            if "attachment" in content_disposition:
                continue

            # Process text/plain
            if content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or 'utf-8'
                    plain_text_parts.append(payload.decode(charset, errors='replace'))
                except Exception as e:
                    log.info(f"Warning: Could not decode text/plain part (charset: {charset}): {e}")
                    # Fallback decoding attempt
                    try:
                        plain_text_parts.append(payload.decode('latin-1', errors='replace'))
                    except Exception:
                        print("Warning: Decoding text/plain using latin-1 also failed.")

            # Process text/html (only if BeautifulSoup is available)
            elif content_type == "text/html" and BS4_AVAILABLE:
                 try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or 'utf-8'
                    # Save the raw, decoded HTML
                    html_parts.append(payload.decode(charset, errors='replace'))
                 except Exception as e:
                    log.info(f"Warning: Could not decode text/html part (charset: {charset}): {e}")
                    # Fallback decoding attempt
                    try:
                        html_parts.append(payload.decode('latin-1', errors='replace'))
                    except Exception:
                         log.info("Warning: Decoding text/html using latin-1 also failed.")

    else:
        # The email is not multipart
        content_type = msg.get_content_type()
        content_disposition = msg.get("Content-Disposition", "").lower()

        # Check if the main part is not an attachment
        if "attachment" not in content_disposition:
            if content_type == "text/plain":
                try:
                    payload = msg.get_payload(decode=True)
                    charset = msg.get_content_charset() or 'utf-8'
                    plain_text_parts.append(payload.decode(charset, errors='replace'))
                except Exception as e:
                     log.info(f"Warning: Could not decode single-part text/plain: {e}")
                     try:
                         plain_text_parts.append(payload.decode('latin-1', errors='replace'))
                     except Exception:
                         log.info("Warning: Decoding single-part text/plain using latin-1 also failed.")

            elif content_type == "text/html" and BS4_AVAILABLE:
                try:
                    payload = msg.get_payload(decode=True)
                    charset = msg.get_content_charset() or 'utf-8'
                    html_parts.append(payload.decode(charset, errors='replace'))
                except Exception as e:
                    log.info(f"Warning: Could not decode single-part text/html: {e}")
                    try:
                         html_parts.append(payload.decode('latin-1', errors='replace'))
                    except Exception:
                         log.info("Warning: Decoding single-part text/html using latin-1 also failed.")

    # --- Result decision ---
    if plain_text_parts:
        # Priority 1: Return combined text/plain parts
        return "\n".join(plain_text_parts).strip()

    elif html_parts and BS4_AVAILABLE:
        # Priority 2: If there's no text/plain but there is HTML and BS4, process the HTML
        full_html = "\n".join(html_parts)
        try:
            soup = BeautifulSoup(full_html, 'html.parser')
            # Use get_text() to extract text without tags
            # separator='\n' adds a new line between text blocks
            # strip=True removes whitespace from the beginning/end of each text fragment
            extracted_text = soup.get_text(separator='\n', strip=True)
            return extracted_text
        except Exception as e:
            log.infoprint(f"Error while processing HTML with BeautifulSoup: {e}")
            # In case of an HTML processing error, return an empty string
            return ""

    elif html_parts and not BS4_AVAILABLE:
        # There is HTML, but BS4 is missing - return an empty string
        log.infoprint("Info: HTML content found, but it cannot be processed without BeautifulSoup4.")
        return ""

    else:
        # Neither text/plain nor text/html was found (or HTML could not be processed)
        return ""

def if_not_in_whitelist(whitelist, mail_from):  
    for item in whitelist:
        if mail_from[-len(item):] == item:
            return False
    return True

class ForwardingHandler(AiosmtpdMessageHandler):

    async def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope) -> str:
        """
        Handles the received email message after the DATA command.
        Modifies the subject if the email is marked as phishing.
        """
        # ... (all existing handle_DATA logic remains unchanged) ...
        peer = session.peer
        mail_from = envelope.mail_from
        if mail_from == "<>":
            mail_from = "noreply@pmpg.pl"
        rcpt_tos = envelope.rcpt_tos
        data = envelope.content  # Raw email data as bytes
        try:
            message = BytesParser().parsebytes(data)
            subject = message.get('Subject', '(No subject)')
            log.info(f"Original email subject: {subject}")
        except Exception as e:
            log.error(f"Error parsing email: {e}")
            return '500 Error processing message'
        
        log.info(f"Received email from {mail_from} for {rcpt_tos} from {peer}")
        await self.handle_message(message, mail_from, rcpt_tos)

        return '250 OK: Message accepted'

    # --- ADDED METHOD ---
    async def handle_message(self, message: Message, mail_from, rcpt_tos) -> None:
        
        try:
            with open(whitelistfilename, "r") as whitelistFile:
                whitelist_json = whitelistFile.read()
                whitelist = json.loads(whitelist_json)
        except:
            log.info(f"Could not open phishing_whitelist.txt")
            whitelist["local"] = []
            whitelist["phishing"] = []
            whitelist["spam"] = []
        
        header = message.get('From', '')
        to_header = []
        if header:
            header =  email.header.decode_header(header)
            for item, enc in header:
                if isinstance(item, bytes):
                    if enc:
                        to_header.append(item.decode(enc))
                    else:
                        to_header.append(item.decode())
                else:
                    to_header.append(item)
        log.info(f"To header: {" ".join(to_header)}, mail_from: {mail_from}")
        if spear_check(" ".join(to_header), whitelist["local"]):
            message = modify_subject(message)
            add_spear_header(message)
            log.info("SPEAR Email marked as spear phishing. Modifying subject.")
        else:
            #maildomain = get_domain(mail_from)
            #log.info(f"From: {mail_from}, Domain: {maildomain}")          

            if if_not_in_whitelist(whitelist['local'], mail_from):
                log.info("Sender not in whitelist")
                classification = classify_email(message)

                # --- Subject modification in case of phishing ---
                if classification['phishing_pred'] == 'phishing':
                    if if_not_in_whitelist(whitelist['phishing'], mail_from):
                        log.info("Sender not in whitelist")
                        message = modify_subject(message)
                    
                # --- Adding header in case of spam ---
                if classification['spam_pred'] == 'spam':
                    if if_not_in_whitelist(whitelist['spam'], mail_from):
                        message = add_header(message)                

        # --- Preparing data for forwarding ---
        try:
            data_to_forward = message.as_bytes()
        except Exception as e:
            log.error(f"Error serializing modified email: {e}")
            return '500 Error serializing message for forwarding'
        # --- Forwarding the email ---
        log.info(f"Forwarding email to {FORWARD_HOST}:{FORWARD_PORT}")
        try:
            smtp_client = aiosmtplib.SMTP(hostname=FORWARD_HOST, port=FORWARD_PORT)
            async with smtp_client:
                await smtp_client.sendmail(mail_from, rcpt_tos, data_to_forward)
            log.info("Email successfully forwarded.")
        except aiosmtplib.SMTPConnectError:
            log.error(f"Could not connect to forwarding server {FORWARD_HOST}:{FORWARD_PORT}")
            return '451 Temporary local error: forwarding failed (connection)'
        # ... (rest of the except blocks remain unchanged) ...
        except Exception as e:
            log.debug("Unexpected error during email forwarding")
            return '500 Unexpected error during forwarding'

# ... (the rest of the run_server and __main__ script remains unchanged) ...

# --- Main function to run the server ---
async def run_server():
    """
    Configures and starts the SMTP server.
    """
    # Now the instance can be created correctly
    handler = ForwardingHandler()
    
    class CustomController(Controller):

        def factory(self):
            # Migitating Outlook RFC standard line limit exceeding
            SMTP.line_length_limit = 100000
            return SMTP(self.handler, **self.SMTP_kwargs)
    
    controller = CustomController(
        handler,
        hostname=LISTEN_HOST,
        port=LISTEN_PORT,
    )

    log.info(f"Starting SMTP server on {LISTEN_HOST}:{LISTEN_PORT}")
    log.info(f"Messages will be classified and forwarded to {FORWARD_HOST}:{FORWARD_PORT}")
    controller.start()

    try:
        await asyncio.Event().wait()
    except (asyncio.CancelledError, KeyboardInterrupt):
        log.info("Received stop signal.")
    finally:
        log.info("Stopping server...")
        controller.stop()
        log.info("Server stopped.")

# --- Startup ---
if __name__ == "__main__":
    
    
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        log.info("Interrupted by user (Ctrl+C)")
