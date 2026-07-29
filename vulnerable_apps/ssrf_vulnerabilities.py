
"""
Server-Side Request Forgery (SSRF) Vulnerability Demo
OWASP A10:2021 - Server-Side Request Forgery
"""
import re
import requests
import urllib.request
from flask import Flask, request
from urllib.parse import urlparse

app = Flask(__name__)

# Whitelist of allowed domains
ALLOWED_DOMAINS = [
    'example.com',
    'trusted-api.com',
    'cdn.example.org'
]

def is_valid_url(url):
    """Validate URL against whitelist and check for safe protocols"""
    try:
        parsed = urlparse(url)
        # Only allow HTTP/HTTPS
        if parsed.scheme not in ('http', 'https'):
            return False
        # Check if domain is in whitelist
        if parsed.hostname not in ALLOWED_DOMAINS:
            return False
        # Block internal/private IPs
        if re.match(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|0\.|255\.|localhost)', parsed.hostname):
            return False
        return True
    except ValueError:
        return False

@app.route('/fetch_url')
def fetch_url():
    """FIXED: SSRF protection via URL validation"""
    url = request.args.get('url')

    if not url or not is_valid_url(url):
        return "Invalid or unauthorized URL", 400

    try:
        response = requests.get(url, timeout=10)
        return response.text
    except Exception as e:
        return str(e), 400

@app.route('/proxy')
def proxy_request():
    """FIXED: SSRF protection in proxy endpoint"""
    target_url = request.args.get('target')

    if not target_url or not is_valid_url(target_url):
        return "Invalid or unauthorized target URL", 400

    headers = {'User-Agent': 'ProxyBot/1.0'}
    try:
        response = requests.get(target_url, headers=headers, timeout=10)
        return response.content
    except Exception as e:
        return str(e), 400

@app.route('/webhook')
def trigger_webhook():
    """FIXED: SSRF protection via webhook validation"""
    webhook_url = request.args.get('webhook_url')
    data = request.args.get('data', '{}')

    if not webhook_url or not is_valid_url(webhook_url):
        return "Invalid or unauthorized webhook URL", 400

    try:
        response = requests.post(webhook_url, data=data, timeout=10)
        return f"Webhook triggered: {response.status_code}"
    except Exception as e:
        return str(e), 400

@app.route('/import_feed')
def import_rss_feed():
    """FIXED: SSRF protection in RSS feed import"""
    feed_url = request.args.get('feed')

    if not feed_url or not is_valid_url(feed_url):
        return "Invalid or unauthorized feed URL", 400

    try:
        response = urllib.request.urlopen(feed_url, timeout=10)
        content = response.read()
        return content
    except Exception as e:
        return str(e), 400

@app.route('/check_link')
def check_link():
    """FIXED: SSRF protection in link checker"""
    link = request.args.get('link')

    if not link or not is_valid_url(link):
        return {'error': 'Invalid or unauthorized link'}, 400

    try:
        response = requests.head(link, timeout=5)
        return {
            'status': response.status_code,
            'url': link
        }
    except Exception as e:
        return {'error': str(e)}, 400

def fetch_avatar(avatar_url):
    """FIXED: SSRF protection in avatar fetching"""
    if not avatar_url or not is_valid_url(avatar_url):
        return None

    try:
        response = requests.get(avatar_url, timeout=10)
        if response.status_code == 200:
            return response.content
        return None
    except:
        return None

@app.route('/screenshot')
def take_screenshot():
    """FIXED: SSRF protection in screenshot service"""
    page_url = request.args.get('url')

    if not page_url or not is_valid_url(page_url):
        return "Invalid or unauthorized URL for screenshot", 400

    try:
        response = requests.get(page_url, timeout=10)
        return f"Screenshot taken of {page_url}"
    except Exception as e:
        return str(e), 400

@app.route('/fetch_image')
def fetch_external_image():
    """FIXED: SSRF protection in image fetching"""
    image_url = request.args.get('img')

    if not image_url or not is_valid_url(image_url):
        return 'Invalid or unauthorized image URL', 400

    try:
        img_data = urllib.request.urlopen(image_url, timeout=10).read()
        return img_data
    except Exception as e:
        return str(e), 400

def download_file(file_url):
    """FIXED: SSRF protection in file download"""
    if not file_url or not is_valid_url(file_url):
        return None

    try:
        response = requests.get(file_url, timeout=10)
        return response.content
    except:
        return None

@app.route('/pdf_generator')
def generate_pdf():
    """FIXED: SSRF protection via PDF generation"""
    html_url = request.args.get('html')

    if not html_url or not is_valid_url(html_url):
        return "Invalid or unauthorized HTML URL", 400

    try:
        html_content = requests.get(html_url, timeout=10).text
        return f"PDF generated from {html_url}"
    except Exception as e:
        return str(e), 400

@app.route('/preview')
def preview_url():
    """FIXED: SSRF protection in URL preview"""
    url = request.args.get('url')

    if not url or not is_valid_url(url):
        return {'error': 'Invalid or unauthorized URL'}, 400

    try:
        response = requests.get(url, timeout=10)
        return {
            'title': 'Preview',
            'content': response.text[:500],
            'status': response.status_code
        }
    except Exception as e:
        return {'error': str(e)}, 400

if __name__ == '__main__':
    app.run()
