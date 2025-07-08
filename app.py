from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from waitress import serve
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from datetime import datetime
import os
from dotenv import load_dotenv
import google.generativeai as genai

from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook

# File processing and OCR
import pytesseract

# Set the path to the Tesseract executable
# Update this path if you installed Tesseract in a different location
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
from PIL import Image
import io
import pdfplumber
import cv2
import numpy as np

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
bcrypt = Bcrypt(app)

# Load environment variables
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# Flask-Dance OAuth setup
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # REMOVE in production for https only

google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
    scope=["profile", "email"],
    redirect_url="/login/google/authorized"
)
facebook_bp = make_facebook_blueprint(
    client_id=os.getenv("FACEBOOK_OAUTH_CLIENT_ID"),
    client_secret=os.getenv("FACEBOOK_OAUTH_CLIENT_SECRET"),
    scope=["email"],
    redirect_url="/login/facebook/authorized"
)
app.register_blueprint(google_bp, url_prefix="/login")
app.register_blueprint(facebook_bp, url_prefix="/login")

# MongoDB setup
client = MongoClient(os.getenv("MONGO_URI"))
db = client.excel_chatbot
users_collection = db.users
chat_history_collection = db.chat_history

# Gemini AI model
model = genai.GenerativeModel('gemini-1.5-flash') # Corrected model name

def get_or_create_oauth_user(email, provider):
    """Find an existing user or create a new one for OAuth logins."""
    user = users_collection.find_one({'email': email})
    if not user:
        user_id = users_collection.insert_one({'email': email, 'password': None, 'oauth_provider': provider}).inserted_id
    else:
        user_id = user['_id']
    return str(user_id)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = users_collection.find_one({'email': email})
        if user and user.get('password') and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/login/google/authorized')
def google_authorized():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return redirect(url_for('login'))
    info = resp.json()
    email = info.get("email")
    user_id = get_or_create_oauth_user(email, 'google')
    session['user_id'] = user_id
    return redirect(url_for('index'))

@app.route('/login/facebook/authorized')
def facebook_authorized():
    if not facebook.authorized:
        return redirect(url_for("facebook.login"))
    resp = facebook.get("/me?fields=id,name,email")
    if not resp.ok:
        return redirect(url_for('login'))
    info = resp.json()
    email = info.get("email")
    if not email:
        return render_template('login.html', error='Facebook login failed: Email not provided.')
    user_id = get_or_create_oauth_user(email, 'facebook')
    session['user_id'] = user_id
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if users_collection.find_one({'email': email}):
            return render_template('signup.html', error='Email already exists')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user_id = users_collection.insert_one({'email': email, 'password': hashed_password}).inserted_id
        session['user_id'] = str(user_id)
        return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/chat', methods=['POST'])
def chat():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401
    
    user_message = request.json.get('message')
    if not user_message:
        return jsonify({'success': False, 'error': 'No message provided'}), 400

    try:
        structured_prompt = f"""
        You are an expert Excel assistant. Please provide a clear, well-structured, and helpful response to the following user query.

        User Query: "{user_message}"

        Format your response using Markdown with the following structure:
        - Start with a clear, concise title using a heading (e.g., `## Title of the Response`).
        - Use bullet points (`-`) or numbered lists (`1.`) for key information, steps, or features.
        - Use bold text (`**text**`) to highlight important terms, functions, or concepts.
        - If you provide code or formulas, enclose them in Markdown code blocks.
        - End with a brief, encouraging summary.

        Your response should be accurate, easy to understand, and directly address the user's question.
        """
        response = model.generate_content(structured_prompt)
        ai_response = response.text

        chat_history_collection.insert_one({
            'user_id': session['user_id'],
            'user_message': user_message,
            'ai_response': ai_response,
            'image_url': None,
            'attachment_text': None,
            'timestamp': datetime.utcnow()
        })
        return jsonify({'success': True, 'ai_response': ai_response})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error from AI service: {e}'}), 500

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    history = chat_history_collection.find({'user_id': session['user_id']}).sort('timestamp', -1)
    return render_template('history.html', history=history)

@app.route('/reprocess/<query>')
def reprocess(query):
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    try:
        # Using the structured prompt for consistency
        structured_prompt = f"""
        You are an expert Excel assistant. Please provide a clear, well-structured, and helpful response to the following user query.

        User Query: "{query}"

        Format your response using Markdown with the following structure:
        - Start with a clear, concise title using a heading (e.g., `## Title of the Response`).
        - Use bullet points (`-`) or numbered lists (`1.`) for key information, steps, or features.
        - Use bold text (`**text**`) to highlight important terms, functions, or concepts.
        - If you provide code or formulas, enclose them in Markdown code blocks.
        - End with a brief, encouraging summary.

        Your response should be accurate, easy to understand, and directly address the user's question.
        """
        response = model.generate_content(structured_prompt)
        ai_response = response.text

        chat_history_collection.insert_one({
            'user_id': session['user_id'],
            'user_message': query, # Changed from 'query' to 'user_message' for consistency
            'ai_response': ai_response,
            'image_url': None,
            'attachment_text': None,
            'timestamp': datetime.utcnow()
        })
        return jsonify({'success': True, 'ai_response': ai_response})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error from AI service: {e}'}), 500

@app.route('/clear_history', methods=['POST'])
def clear_history():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401
    chat_history_collection.delete_many({'user_id': session['user_id']})
    return jsonify({'success': True})

def extract_text_from_file(file_bytes, filename, mimetype):
    """Extracts text from file bytes and returns the text and an error if any."""
    extracted_text = ''
    error = None
    try:
        if filename.lower().endswith('.pdf'):
            with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
                for page in pdf.pages:
                    extracted_text += page.extract_text() or ''
        elif mimetype.startswith('image/'):
            img = Image.open(io.BytesIO(file_bytes)).convert('RGB')
            open_cv_img = np.array(img)
            open_cv_img = open_cv_img[:, :, ::-1].copy()
            gray = cv2.cvtColor(open_cv_img, cv2.COLOR_BGR2GRAY)
            _, thresh = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY)
            extracted_text = pytesseract.image_to_string(thresh)
        else:
            error = 'Unsupported file type'
    except Exception as e:
        error = f'Error processing file: {e}'
    return extracted_text, error

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    user_message = request.form.get('message', '')
    file = request.files.get('file')
    extracted_text = ''
    image_url = None
    ai_response = ""

    if file and file.filename != '':
        file_bytes = file.read()
        filename = secure_filename(file.filename)
        mimetype = file.mimetype

        if mimetype.startswith('image/'):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(filepath, 'wb') as f:
                f.write(file_bytes)
            image_url = url_for('static', filename=f'uploads/{filename}')

        extracted_text, error = extract_text_from_file(file_bytes, filename, mimetype)
        if error:
            print(f"ERROR during text extraction: {error}")

    full_prompt = user_message
    if extracted_text:
        full_prompt += f'\n\n[Content from attachment]:\n{extracted_text}'

    if not full_prompt.strip():
        if image_url:
            ai_response = "Received your image. What would you like to know about it?"
        else:
            return jsonify({'success': False, 'error': 'No message or processable file content.'}), 400
    else:
        try:
            structured_prompt = f"""
            You are an expert Excel assistant. Please provide a clear, well-structured, and helpful response to the following user query.

            User Query: "{full_prompt}"

            Format your response using Markdown with the following structure:
            - Start with a clear, concise title using a heading (e.g., `## Title of the Response`).
            - Use bullet points (`-`) or numbered lists (`1.`) for key information, steps, or features.
            - Use bold text (`**text**`) to highlight important terms, functions, or concepts.
            - If you provide code or formulas, enclose them in Markdown code blocks.
            - End with a brief, encouraging summary.

            Your response should be accurate, easy to understand, and directly address the user's question.
            """
            response = model.generate_content(structured_prompt)
            ai_response = response.text
        except Exception as e:
            return jsonify({'success': False, 'error': f'AI generation failed: {e}'}), 500

    chat_history_collection.insert_one({
        'user_id': session['user_id'],
        'user_message': user_message,
        'ai_response': ai_response,
        'image_url': image_url,
        'attachment_text': extracted_text,
        'timestamp': datetime.utcnow()
    })

    return jsonify({'success': True, 'ai_response': ai_response, 'image_url': image_url})

if __name__ == '__main__':
    # Use Waitress as the production server
    # The app will be accessible on your local network at http://<your-ip-address>:8080
    print("Starting server on http://0.0.0.0:8080")
    serve(app, host='0.0.0.0', port=8080)
