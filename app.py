from flask import Flask, request, send_file
from redaction import redact_pdf

app = Flask(__name__)

@app.route('/redact-pdf', methods=['POST'])
def redact_pdf_endpoint():
  pdf_file = request.files['pdf_file']

  if pdf_file and pdf_file.filename.endswith('.pdf'):
    # Save the uploaded PDF temporarily
    pdf_path = 'temp.pdf'
    pdf_file.save(pdf_path)

    # Redact the PDF
    redacted_pdf_path = redact_pdf(pdf_path)

    # Send the redacted PDF as a response
    return send_file(redacted_pdf_path, as_attachment=True, download_name='redacted.pdf')

  return 'Invalid PDF file. Please upload a PDF.', 400

if __name__ == '__main__':
  app.run(debug=True)
