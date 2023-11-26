from google.cloud import dlp_v2
from cryptography.fernet import Fernet
import fitz  # PyMuPDF

def encrypt_data(data, key):
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data

def redact_pdf(pdf_path):
    # Initialize DLP client
    dlp_client = dlp_v2.DlpServiceClient()

    # Read PDF content
    doc = fitz.open(pdf_path)
    pdf_text = ""
    for page_num in range(doc.page_count):
        page = doc[page_num]
        pdf_text += page.get_text("text")

    # Configure the inspection request
    inspect_config = {
        "info_types": [{"name": "PERSON_NAME"}, {"name": "US_SOCIAL_SECURITY_NUMBER"}],
        "include_quote": True,
    }

    # Run DLP inspection
    response = dlp_client.inspect_content(
        parent="projects/your-google-cloud-project-id",
        item={"value": pdf_text},
        inspect_config=inspect_config,
    )

    # Encrypt and redact sensitive data
    redacted_pdf_text = pdf_text
    for result in response.result.findings:
        if result.quote_info:
            quote = result.quote_info.quoted_text
            encrypted_data = encrypt_data(quote, Fernet.generate_key())
            redacted_pdf_text = redacted_pdf_text.replace(quote, encrypted_data.decode())

    # Save the redacted PDF
    redacted_pdf_path = 'redacted.pdf'
    redacted_doc = fitz.open()
    redacted_page = redacted_doc.new_page(width=page.rect.width, height=page.rect.height)
    redacted_page.insert_text((0, 0), redacted_pdf_text)
    redacted_doc.save(redacted_pdf_path)
    redacted_doc.close()

    return redacted_pdf_path
