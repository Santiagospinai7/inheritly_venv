from google.cloud import dlp_v2
from cryptography.fernet import Fernet
import fitz  # PyMuPDF

def encrypt_data(data, key):
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data

def redact_pdf(pdf_path):
    # Initialize DLP client
    dlp_client = dlp_v2.DlpServiceClient(credentials="-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDiBeJEO0i4VO5x\n20aHbYoGRcR8mMmE/2Ljwcg0sPc/Lhu7IKUsdrhm0rJqGbm93INe4cPmAhCL77Av\nZ3hNKCIjoT9G2faiHBRjwNOAur5uncZWcUjpE4rJVteCzySp4COk+EZqFwQ8tx4u\nZotinZ+Xn/jglq2eaqafYK18V79oy/NBEywasUoMjfJ8nP8DsQcYHaD/4jJrsYq8\nhrH3V4BpFii8Jvb55TvQVbDSR3YEfWY5PVn0zrFAepSFVqSdlAvnArLrR6iI7SDx\nNl3LL9A/LJsjS3DD3sSo8OBqUfbQvxxs7hQx6WGSOH5fv3BqhMfz7RSliRd8UzK+\nANMub8eLAgMBAAECggEAAbqj/M5pnoUOhWbHtXli65F+OhWHEo0R3CVYMu+CN8zv\nNV/YjvzoOcbSeAHWHbrO9z6HrCc7HbC+fkzLoK0GobQtw0q8WHf4t3GcD7Kwmuab\nw/LQv8e2K0BlNUcqEoJbWijTCNGCEGcqFtinRNZQPgqSzKN9jIcVgCLBpq2rnqw/\nILtgi7GMEc+aoG2fClxhoJuug93DgsNsMC3J92KJZkCKN2UdxTHNGKGB2HMDPaNa\n1IM1lySwv7eT/nLHMHaxnxDpROZqDwj7DOHLnsI+j0UFlm90YAdcuwO6VBja1bRJ\nWAs5HLhF7fnaL0Z/RpRKIqlD4RuSOSBDgZP6HlQEQQKBgQD6lmrrUBzabSodmO/A\nBWWqoi0zu/xLZGOjeiFC8bGWvUGPYR60bjtQP8wFpkbezOc15qEDONBAWYL5YepP\nPzgnA+DLG2NrfrormMVjNqAY9oVE/QJPa1yxWba9a5eS6mrlxcTlQElq9ZQO0Q5e\nICuiKWgzfwOS7fLCpa9gpgarEQKBgQDm56PxrPMadpvGpDvUwuWbNLxDuW2VUwZc\nA+HRcwaHhszymTT+lxVMMka3QFF1lFi1agvD7M3F+8jxCkntp+oZOXe3L44Qa3Fw\nyX+DibGIuFBCO4/OsSj45PuEoO2aGhpTFC0bNQsoXEBWvEyLZjWZftvNuKx3+nHW\noOZwVaRw2wKBgQDmCxh0lcMnMngrW68dVNcUYnWkvLrMa4idFw1Z64/gljWNbtdF\nRLzm2uptdUwyVWEctnCyCIIF0SbP0ffMcHkYOBMx4h7PHDPEuibbAdbPk+CciLiK\nOEGL/pQoKJGpqdIgxgIPg4jizDfzsi/CcT4dTG4AeGXLiO4HixsJWuFcQQKBgAMe\nO6uGz12bHm1nSFuOKjWXV7d+aIlsrphNgR4n9H2eB2R7Ryjs91+pCiVtW+w/jZcd\nkH0b1IeI5+TBY9AuxU2D5ib2IG/+U3DXd75Z/KjA/Gx4i2+aGtiJlw/qcGr1UUev\n7RAB/l2UKVZCgrIbNjwVZ3h2tvWDz0e7soDv1yGjAoGBAJP5/QpLik9j9QsRudwh\nmqDRuKw/jj0f+RKDtBdQpJ+6uvKUN+D20YAMHkygQDWgbe+M7RMJmhbtONiuMFgS\nw+1lI+wCcq7fQZJQQ6aFMvFhNccrhhEEx4nDubk6LsViZrhi9WSnksl72Dh7pGPv\n/U+OBdEyVMee//mEiIw7+v0V\n-----END PRIVATE KEY-----\n",)

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
        request={
            "parent": "inheritlytest",
            "item": {"value": pdf_text},
            "inspect_config": inspect_config,
        }
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
