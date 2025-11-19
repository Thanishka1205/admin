from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, jsonify
from flask_socketio import SocketIO, emit
import bcrypt
import logging
from db_config import get_db_connection
from functools import wraps
import csv
from io import StringIO
import traceback
import boto3
from botocore.exceptions import ClientError
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True for HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialize SocketIO for admin
socketio = SocketIO(app, cors_allowed_origins="*")

# Enable logging
logging.basicConfig(level=logging.DEBUG)

# AWS S3 configuration
S3_BUCKET = os.getenv('S3_BUCKET')
S3_REGION = os.getenv('S3_REGION')
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
S3_VIDEO_PREFIX = os.getenv('S3_VIDEO_PREFIX', 'Interview-questions/interview-videos/')

# Validate required AWS environment variables
if not all([S3_BUCKET, S3_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY]):
    raise ValueError("Missing required AWS environment variables. Please check your .env file.")

s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=S3_REGION
)

# Decorator to enforce login requirement
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# SocketIO events for WebRTC
@socketio.on('connect')
def handle_connect():
    if session.get('admin_logged_in'):
        app.logger.info("Admin connected to SocketIO")
        emit('admin_connected', broadcast=True)

@socketio.on('offer')
def handle_offer(data):
    if session.get('admin_logged_in'):
        emit('offer', {
            'candidate_id': data['candidate_id'],
            'offer': data['offer']
        }, broadcast=True)

@socketio.on('answer')
def handle_answer(data):
    if session.get('admin_logged_in'):
        emit('answer', {
            'candidate_id': data['candidate_id'],
            'answer': data['answer']
        }, broadcast=True)

@socketio.on('ice_candidate')
def handle_ice_candidate(data):
    if session.get('admin_logged_in'):
        emit('ice_candidate', {
            'candidate_id': data['candidate_id'],
            'candidate': data['candidate']
        }, broadcast=True)

@app.route('/', methods=['GET', 'POST'])
def login():
    if session.get('admin_logged_in'):
        return redirect(url_for('dashboard'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            error = "Username and password are required."
        else:
            try:
                password = password.encode('utf-8')
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT password_hash FROM admin_users WHERE username = %s", (username,))
                result = cursor.fetchone()
                conn.close()
                if result and bcrypt.checkpw(password, result[0].encode()):
                    session['admin_logged_in'] = True
                    return redirect(url_for('dashboard'))
                else:
                    error = "Invalid credentials. Please try again."
            except Exception as e:
                app.logger.error(f"Login error: {str(e)}")
                error = "Database connection error. Please try again later."
    return render_template('login.html', error=error)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/view_candidates')
@login_required
def view_candidates():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM candidates")
        candidates = cursor.fetchall()
        conn.close()
        return render_template('candidates.html', candidates=candidates)
    except Exception as e:
        app.logger.error(f"View candidates error: {str(e)}")
        flash('Error loading candidates. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/download_candidates_csv')
@login_required
def download_candidates_csv():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                id,
                full_name,
                email,
                phone,
                city,
                position,
                has_experience,
                years_experience,
                tech_stack,
                submitted_at
            FROM candidates 
            ORDER BY submitted_at DESC
        """)
        candidates = cursor.fetchall()
        conn.close()
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            'Candidate ID',
            'Full Name',
            'Email',
            'Phone',
            'City',
            'Position',
            'Has Experience',
            'Years of Experience',
            'Tech Stack',
            'Submission Date'
        ])
        for candidate in candidates:
            writer.writerow([
                candidate['id'],
                candidate['full_name'],
                candidate['email'],
                candidate['phone'] if candidate['phone'] else 'N/A',
                candidate['city'] if candidate['city'] else 'N/A',
                candidate['position'] if candidate['position'] else 'N/A',
                'Yes' if candidate['has_experience'] else 'No',
                candidate['years_experience'] if candidate['years_experience'] else 'N/A',
                candidate['tech_stack'] if candidate['tech_stack'] else 'N/A',
                candidate['submitted_at'].strftime('%Y-%m-%d %I:%M:%S %p IST') if candidate['submitted_at'] else 'N/A'
            ])
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=candidates.csv'
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except Exception as e:
        app.logger.error(f"Download candidates CSV error: {str(e)}")
        flash('Error downloading candidates data. Please try again later.', 'danger')
        return redirect(url_for('view_candidates'))

@app.route('/view_scores')
@login_required
def view_scores():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) as count FROM candidates")
        count_result = cursor.fetchone()
        cursor.execute("""
            WITH candidate_counts AS (
                SELECT 
                    email,
                    COUNT(id) as total_attempts
                FROM candidates
                GROUP BY email
            ),
            latest_candidate AS (
                SELECT 
                    id AS candidate_id, 
                    full_name, 
                    email, 
                    submitted_at,
                    ROW_NUMBER() OVER (PARTITION BY email ORDER BY submitted_at DESC) AS rn
                FROM candidates
            )
            SELECT 
                lc.candidate_id,
                lc.full_name,
                lc.email,
                cc.total_attempts,
                s.score_id,
                s.attempt_number,
                s.total_questions,
                s.correct_answers,
                s.score_percent,
                s.submitted_at
            FROM latest_candidate lc
            JOIN candidate_counts cc ON lc.email = cc.email
            LEFT JOIN scores s ON lc.email = (
                SELECT email FROM candidates c WHERE c.id = s.candidate_id
            )
            WHERE lc.rn = 1
            ORDER BY lc.email, s.submitted_at;
        """)
        results = cursor.fetchall()
        conn.close()
        candidates = {}
        for row in results:
            email = row['email']
            if email not in candidates:
                candidates[email] = {
                    'candidate_id': row['candidate_id'],
                    'full_name': row['full_name'],
                    'email': email,
                    'total_attempts': row['total_attempts'],
                    'attempts': []
                }
            if row['score_id']:
                candidates[email]['attempts'].append({
                    'score_id': row['score_id'],
                    'attempt_number': row['attempt_number'],
                    'total_questions': row['total_questions'],
                    'correct_answers': row['correct_answers'],
                    'score_percent': row['score_percent'],
                    'submitted_at': row['submitted_at']
                })
        for email in candidates:
            attempts = candidates[email]['attempts']
            attempts.sort(key=lambda x: x['submitted_at'])
            for i, attempt in enumerate(attempts, start=1):
                attempt['attempt_number'] = i
        return render_template('scores.html', candidates=list(candidates.values()))
    except Exception as e:
        app.logger.error(f"View scores error: {str(e)}")
        flash('Error loading scores. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/view_scores_by_set', methods=['GET', 'POST'])
@login_required
def view_scores_by_set():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT DISTINCT set_number FROM questions ORDER BY set_number")
        sets = [row['set_number'] for row in cursor.fetchall()]
        selected_set = request.form.get('set_number', sets[0] if sets else None)
        if selected_set:
            selected_set = int(selected_set)
        if not sets:
            conn.close()
            return render_template('scores_by_set.html', sets=sets, selected_set=None, scores=[])
        cursor.execute("""
            SELECT 
                c.id AS candidate_id,
                c.full_name,
                c.email,
                s.score_id,
                s.attempt_number,
                s.total_questions,
                s.correct_answers,
                s.score_percent,
                s.submitted_at,
                q.set_number
            FROM scores s
            JOIN candidates c ON s.candidate_id = c.id
            JOIN answers a ON a.score_id = s.score_id
            JOIN questions q ON a.question_id = q.question_id
            WHERE q.set_number = %s
            GROUP BY s.score_id, c.id, c.full_name, c.email, s.attempt_number, 
                     s.total_questions, s.correct_answers, s.score_percent, s.submitted_at, q.set_number
            ORDER BY c.email, s.attempt_number;
        """, (selected_set,))
        scores = cursor.fetchall()
        conn.close()
        return render_template('scores_by_set.html', sets=sets, selected_set=selected_set, scores=scores)
    except Exception as e:
        app.logger.error(f"View scores by set error: {str(e)}")
        flash('Error loading scores by set. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/view_answers_by_set/<int:score_id>')
@login_required
def view_answers_by_set(score_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                c.id AS candidate_id,
                c.full_name,
                c.email,
                s.score_id,
                s.attempt_number,
                s.total_questions,
                s.correct_answers,
                s.score_percent,
                s.submitted_at,
                q.set_number
            FROM scores s
            JOIN candidates c ON s.candidate_id = c.id
            JOIN answers a ON a.score_id = s.score_id
            JOIN questions q ON a.question_id = q.question_id
            WHERE s.score_id = %s
            GROUP BY s.score_id, c.id, c.full_name, c.email, s.attempt_number, 
                     s.total_questions, s.correct_answers, s.score_percent, s.submitted_at, q.set_number
        """, (score_id,))
        score = cursor.fetchone()
        if not score:
            conn.close()
            flash('Score not found.', 'danger')
            return redirect(url_for('view_scores_by_set'))
        cursor.execute("""
            SELECT 
                a.answer_id, 
                a.selected_option, 
                a.is_correct, 
                a.answered_at,
                q.question_id, 
                q.set_number, 
                q.category, 
                q.question_text, 
                q.option_a, 
                q.option_b, 
                q.option_c, 
                q.option_d, 
                q.correct_option
            FROM answers a
            JOIN questions q ON a.question_id = q.question_id
            WHERE a.score_id = %s
            ORDER BY q.category, q.question_id
        """, (score_id,))
        answers = cursor.fetchall()
        conn.close()
        return render_template('view_answers_by_set.html', score=score, answers=answers)
    except Exception as e:
        app.logger.error(f"View answers by set error: {str(e)}")
        flash('Error loading answers. Please try again later.', 'danger')
        return redirect(url_for('view_scores_by_set'))

@app.route('/view_answers/<int:score_id>')
@login_required
def view_answers(score_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                c.id AS candidate_id,
                c.full_name,
                c.email,
                s.score_id,
                s.attempt_number,
                s.total_questions,
                s.correct_answers,
                s.score_percent,
                s.submitted_at,
                q.set_number
            FROM scores s
            JOIN candidates c ON s.candidate_id = c.id
            JOIN answers a ON a.score_id = s.score_id
            JOIN questions q ON a.question_id = q.question_id
            WHERE s.score_id = %s
            GROUP BY s.score_id, c.id, c.full_name, c.email, s.attempt_number, 
                     s.total_questions, s.correct_answers, s.score_percent, s.submitted_at, q.set_number
        """, (score_id,))
        score = cursor.fetchone()
        if not score:
            conn.close()
            flash('Score not found.', 'danger')
            return redirect(url_for('view_scores'))
        cursor.execute("""
            SELECT 
                a.answer_id, 
                a.selected_option, 
                a.is_correct, 
                a.answered_at,
                q.question_id, 
                q.set_number, 
                q.category, 
                q.question_text, 
                q.option_a, 
                q.option_b, 
                q.option_c, 
                q.option_d, 
                q.correct_option
            FROM answers a
            JOIN questions q ON a.question_id = q.question_id
            WHERE a.score_id = %s
            ORDER BY q.category, q.question_id
        """, (score_id,))
        answers = cursor.fetchall()
        conn.close()
        return render_template('view_answers.html', score=score, answers=answers)
    except Exception as e:
        app.logger.error(f"View answers error: {str(e)}")
        flash('Error loading answers. Please try again later.', 'danger')
        return redirect(url_for('view_scores'))

@app.route('/monitor_test')
@login_required
def monitor_test():
    try:
        # Fetch all videos from S3 bucket
        videos = []
        try:
            response = s3_client.list_objects_v2(
                Bucket=S3_BUCKET,
                Prefix=S3_VIDEO_PREFIX
            )
            
            if 'Contents' in response:
                for obj in response['Contents']:
                    # Skip if it's just a folder (ends with /)
                    if obj['Key'].endswith('/'):
                        continue
                    
                    # Extract filename and parse candidate info
                    filename = obj['Key'].split('/')[-1]
                    file_size = obj['Size']
                    last_modified = obj['LastModified']
                    
                    # Parse candidate ID and attempt from filename
                    # Format: candidate{candidate_id}attempt{attempt_number}{timestamp}.webm
                    candidate_id = None
                    attempt_number = None
                    if filename.startswith('candidate') and 'attempt' in filename:
                        try:
                            parts = filename.replace('.webm', '').split('attempt')
                            if len(parts) == 2:
                                candidate_id_str = parts[0].replace('candidate', '')
                                candidate_id = int(candidate_id_str) if candidate_id_str.isdigit() else None
                                attempt_parts = parts[1]
                                # Extract attempt number (everything before the timestamp)
                                attempt_number = None
                                for i, char in enumerate(attempt_parts):
                                    if char.isdigit():
                                        attempt_str = ''
                                        j = i
                                        while j < len(attempt_parts) and attempt_parts[j].isdigit():
                                            attempt_str += attempt_parts[j]
                                            j += 1
                                        if attempt_str:
                                            attempt_number = int(attempt_str)
                                            break
                        except (ValueError, IndexError):
                            pass
                    
                    videos.append({
                        'key': obj['Key'],
                        'filename': filename,
                        'size': file_size,
                        'last_modified': last_modified,
                        'candidate_id': candidate_id,
                        'attempt_number': attempt_number
                    })
                
                # Sort by last modified (newest first)
                videos.sort(key=lambda x: x['last_modified'], reverse=True)
        except ClientError as e:
            app.logger.error(f"Error fetching videos from S3: {str(e)}")
            flash('Error fetching videos from S3. Please check your S3 configuration.', 'danger')
        except Exception as e:
            app.logger.error(f"Unexpected error fetching videos: {str(e)}")
        
        return render_template('monitor_test.html', videos=videos)
    except Exception as e:
        app.logger.error(f"Monitor test error: {str(e)} with traceback: {traceback.format_exc()}")
        flash('Error loading monitoring page. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/view_video/<path:s3_key>')
@login_required
def view_video(s3_key):
    """Generate a signed URL for viewing a video from S3"""
    try:
        # Validate that the key starts with the expected prefix for security
        if not s3_key.startswith(S3_VIDEO_PREFIX):
            flash('Invalid video path.', 'danger')
            return redirect(url_for('monitor_test'))
        
        # Generate a presigned URL that expires in 1 hour
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': S3_BUCKET,
                'Key': s3_key
            },
            ExpiresIn=3600  # 1 hour
        )
        
        filename = s3_key.split('/')[-1]
        return render_template('view_video.html', video_url=presigned_url, filename=filename)
    except ClientError as e:
        app.logger.error(f"Error generating presigned URL: {str(e)}")
        flash('Error loading video. Please try again later.', 'danger')
        return redirect(url_for('monitor_test'))
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        flash('Error loading video. Please try again later.', 'danger')
        return redirect(url_for('monitor_test'))

@app.route('/monitor_video/<int:candidate_id>')
@login_required
def monitor_video(candidate_id):
    """Legacy route for live video monitoring (WebRTC)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, full_name, email FROM candidates WHERE id = %s", (candidate_id,))
        candidate = cursor.fetchone()
        conn.close()
        if not candidate:
            flash('Candidate not found.', 'danger')
            return redirect(url_for('monitor_test'))
        return render_template('monitor_video.html', candidate=candidate)
    except Exception as e:
        app.logger.error(f"Monitor video error: {str(e)}")
        flash('Error loading video stream. Please try again later.', 'danger')
        return redirect(url_for('monitor_test'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/view_tab_switches')
@login_required
def view_tab_switches():
    """View tab switch monitoring data for all candidates"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get tab switch data with candidate information
        cursor.execute("""
            SELECT 
                ts.switch_id,
                ts.candidate_id,
                ts.attempt_number,
                ts.switch_type,
                ts.switched_at,
                c.full_name,
                c.email
            FROM tab_switches ts
            JOIN candidates c ON ts.candidate_id = c.id
            ORDER BY ts.switched_at DESC
        """)
        switches = cursor.fetchall()
        
        # Aggregate switch counts by candidate
        cursor.execute("""
            SELECT 
                c.id AS candidate_id,
                c.full_name,
                c.email,
                COUNT(DISTINCT ts.attempt_number) AS total_attempts,
                COUNT(CASE WHEN ts.switch_type = 'switch_out' THEN 1 END) AS total_switch_outs,
                COUNT(CASE WHEN ts.switch_type = 'switch_back' THEN 1 END) AS total_switch_backs,
                COUNT(*) AS total_switches,
                MAX(ts.switched_at) AS last_switch_time
            FROM candidates c
            LEFT JOIN tab_switches ts ON c.id = ts.candidate_id
            GROUP BY c.id, c.full_name, c.email
            HAVING total_switches > 0
            ORDER BY total_switches DESC, last_switch_time DESC
        """)
        candidate_stats = cursor.fetchall()
        
        conn.close()
        
        return render_template('tab_switches.html', 
                             switches=switches, 
                             candidate_stats=candidate_stats)
    except Exception as e:
        app.logger.error(f"View tab switches error: {str(e)}")
        flash('Error loading tab switch data. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/test')
@login_required
def test():
    return "Admin app is working!"

if __name__ == '__main__':
    print("Starting Flask Admin Application on port 5001...")
    socketio.run(app, debug=True, host='0.0.0.0', port=5001)