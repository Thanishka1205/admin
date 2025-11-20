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

# Initialize S3 client only if credentials are available
s3_client = None
if all([S3_BUCKET, S3_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY]):
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=S3_REGION
        )
    except Exception as e:
        logging.warning(f"Failed to initialize S3 client: {str(e)}")
        s3_client = None
else:
    logging.warning("S3 configuration incomplete. Video monitoring will not be available.")

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
            conn = None
            try:
                password = password.encode('utf-8')
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT password_hash FROM admin_users WHERE username = %s", (username,))
                result = cursor.fetchone()
                if result and bcrypt.checkpw(password, result[0].encode()):
                    session['admin_logged_in'] = True
                    return redirect(url_for('dashboard'))
                else:
                    error = "Invalid credentials. Please try again."
            except Exception as e:
                app.logger.error(f"Login error: {str(e)}")
                app.logger.error(f"Traceback: {traceback.format_exc()}")
                error = "Database connection error. Please try again later."
            finally:
                if conn and conn.is_connected():
                    conn.close()
    return render_template('login.html', error=error)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/view_candidates')
@login_required
def view_candidates():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM candidates ORDER BY submitted_at DESC")
        candidates = cursor.fetchall()
        return render_template('candidates.html', candidates=candidates)
    except Exception as e:
        app.logger.error(f"View candidates error: {str(e)}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        flash('Error loading candidates. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

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
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # First, get all unique candidate_ids from scores
        cursor.execute("""
            SELECT DISTINCT candidate_id
            FROM scores
            WHERE candidate_id IS NOT NULL
            ORDER BY candidate_id
        """)
        unique_candidate_ids = [row['candidate_id'] for row in cursor.fetchall()]
        
        # Fetch candidate info for each unique candidate_id to ensure correct mapping
        # Query each candidate individually using candidate_id column from candidates table
        candidate_info_map = {}
        if unique_candidate_ids:
            # Use a single query with IN clause to avoid multiple queries
            placeholders = ','.join(['%s'] * len(unique_candidate_ids))
            cursor.execute(f"""
                SELECT candidate_id, full_name, email
                FROM candidates
                WHERE candidate_id IN ({placeholders})
            """, tuple(unique_candidate_ids))
            candidate_records = cursor.fetchall()
            
            for candidate_record in candidate_records:
                candidate_id = candidate_record['candidate_id']
                candidate_info_map[candidate_id] = {
                    'full_name': candidate_record['full_name'],
                    'email': candidate_record['email']
                }
                # Log for debugging - use INFO level so it's visible
                app.logger.info(f"Fetched Candidate ID {candidate_id}: Name='{candidate_record['full_name']}', Email='{candidate_record['email']}'")
        
        # Now get all scores
        cursor.execute("""
            SELECT 
                candidate_id,
                score_id,
                attempt_number,
                total_questions,
                correct_answers,
                score_percent,
                submitted_at
            FROM scores
            WHERE candidate_id IS NOT NULL
            ORDER BY candidate_id, submitted_at ASC
        """)
        results = cursor.fetchall()
        
        # Group by candidate_id and collect all attempts with correct candidate info
        candidates = {}
        for row in results:
            candidate_id = row['candidate_id']
            
            # Skip if we don't have candidate info for this candidate_id
            if candidate_id not in candidate_info_map:
                app.logger.warning(f"No candidate info found for candidate_id: {candidate_id}")
                continue
            
            # Initialize candidate entry if not exists, using the correct candidate info from map
            if candidate_id not in candidates:
                # Get the candidate info directly from the map to ensure we use the correct one
                if candidate_id in candidate_info_map:
                    candidate_info = candidate_info_map[candidate_id]
                    candidates[candidate_id] = {
                        'candidate_id': candidate_id,
                        'full_name': str(candidate_info['full_name']),  # Ensure it's a string
                        'email': str(candidate_info['email']),  # Ensure it's a string
                        'total_attempts': 0,
                        'attempts': []
                    }
                    # Log for debugging - use INFO level so it's visible
                    app.logger.info(f"Initialized candidate entry: ID={candidate_id}, Name='{candidate_info['full_name']}', Email='{candidate_info['email']}'")
                else:
                    app.logger.error(f"Candidate ID {candidate_id} not found in candidate_info_map!")
                    continue
            
            # Add attempt
            candidates[candidate_id]['attempts'].append({
                'score_id': row['score_id'],
                'attempt_number': row['attempt_number'],
                'total_questions': row['total_questions'],
                'correct_answers': row['correct_answers'],
                'score_percent': float(row['score_percent']) if row['score_percent'] else 0.0,
                'submitted_at': row['submitted_at']
            })
        
        # Update total_attempts and ensure attempt numbers are sequential
        for candidate_id in candidates:
            attempts = candidates[candidate_id]['attempts']
            candidates[candidate_id]['total_attempts'] = len(attempts)
            # Sort attempts by submitted_at and renumber them
            attempts.sort(key=lambda x: x['submitted_at'] if x['submitted_at'] else '')
            for i, attempt in enumerate(attempts, start=1):
                attempt['attempt_number'] = i
        
        # Final verification - log the candidate info being returned
        for candidate_id, candidate_data in candidates.items():
            app.logger.info(f"Final candidate {candidate_id}: {candidate_data['full_name']} ({candidate_data['email']}) - {candidate_data['total_attempts']} attempts")
        
        return render_template('scores.html', candidates=list(candidates.values()))
    except Exception as e:
        app.logger.error(f"View scores error: {str(e)}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        flash('Error loading scores. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if conn and conn.is_connected():
            conn.close()

@app.route('/view_scores_by_set', methods=['GET', 'POST'])
@login_required
def view_scores_by_set():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT DISTINCT set_number FROM questions ORDER BY set_number")
        sets = [row['set_number'] for row in cursor.fetchall()]
        
        # Get selected set from form or default to first set
        selected_set = request.form.get('set_number') or request.args.get('set_number')
        if selected_set:
            selected_set = int(selected_set)
        elif sets:
            selected_set = sets[0]
        
        if not sets:
            return render_template('scores_by_set.html', sets=sets, selected_set=None, scores=[])
        
        # First, get unique candidate_ids from scores for the selected set
        cursor.execute("""
            SELECT DISTINCT s.candidate_id
            FROM scores s
            INNER JOIN answers a ON a.score_id = s.score_id
            INNER JOIN questions q ON a.question_id = q.question_id
            WHERE q.set_number = %s AND s.candidate_id IS NOT NULL
            ORDER BY s.candidate_id
        """, (selected_set,))
        unique_candidate_ids = [row['candidate_id'] for row in cursor.fetchall()]
        
        # Fetch candidate info for each unique candidate_id using candidate_id column
        candidate_info_map = {}
        if unique_candidate_ids:
            placeholders = ','.join(['%s'] * len(unique_candidate_ids))
            cursor.execute(f"""
                SELECT candidate_id, full_name, email
                FROM candidates
                WHERE candidate_id IN ({placeholders})
            """, tuple(unique_candidate_ids))
            candidate_records = cursor.fetchall()
            
            for candidate_record in candidate_records:
                candidate_id = candidate_record['candidate_id']
                candidate_info_map[candidate_id] = {
                    'full_name': candidate_record['full_name'],
                    'email': candidate_record['email']
                }
                app.logger.info(f"Fetched Candidate ID {candidate_id} for set {selected_set}: Name='{candidate_record['full_name']}', Email='{candidate_record['email']}'")
        
        # Get scores for candidates who attempted the selected set
        # Only show scores where the answers belong to questions in the selected set
        cursor.execute("""
            SELECT DISTINCT
                s.candidate_id,
                s.score_id,
                s.attempt_number,
                s.total_questions,
                s.correct_answers,
                s.score_percent,
                s.submitted_at
            FROM scores s
            INNER JOIN answers a ON a.score_id = s.score_id
            INNER JOIN questions q ON a.question_id = q.question_id
            WHERE q.set_number = %s AND s.candidate_id IS NOT NULL
            GROUP BY s.score_id, s.candidate_id, s.attempt_number, 
                     s.total_questions, s.correct_answers, s.score_percent, s.submitted_at
            ORDER BY s.candidate_id, s.submitted_at ASC
        """, (selected_set,))
        score_results = cursor.fetchall()
        
        # Combine scores with candidate info
        scores = []
        for score_row in score_results:
            candidate_id = score_row['candidate_id']
            if candidate_id in candidate_info_map:
                candidate_info = candidate_info_map[candidate_id]
                score_data = {
                    'candidate_id': candidate_id,
                    'full_name': candidate_info['full_name'],
                    'email': candidate_info['email'],
                    'score_id': score_row['score_id'],
                    'attempt_number': score_row['attempt_number'],
                    'total_questions': score_row['total_questions'],
                    'correct_answers': score_row['correct_answers'],
                    'score_percent': score_row['score_percent'],
                    'submitted_at': score_row['submitted_at']
                }
                scores.append(score_data)
        
        return render_template('scores_by_set.html', sets=sets, selected_set=selected_set, scores=scores)
    except Exception as e:
        app.logger.error(f"View scores by set error: {str(e)}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        flash('Error loading scores by set. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if conn and conn.is_connected():
            conn.close()

@app.route('/view_answers_by_set/<int:score_id>')
@login_required
def view_answers_by_set(score_id):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                s.candidate_id,
                c.full_name,
                c.email,
                s.score_id,
                s.attempt_number,
                s.total_questions,
                s.correct_answers,
                s.score_percent,
                s.submitted_at
            FROM scores s
            JOIN candidates c ON s.candidate_id = c.candidate_id
            WHERE s.score_id = %s
        """, (score_id,))
        score = cursor.fetchone()
        if not score:
            flash('Score not found.', 'danger')
            return redirect(url_for('view_scores_by_set'))
        
        # Fetch questions and answers for this specific score_id
        # All answers linked to this score_id belong to the same attempt and set
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
            ORDER BY q.set_number, q.category, q.question_id
        """, (score_id,))
        answers = cursor.fetchall()
        
        if not answers:
            flash('No answers found for this score.', 'danger')
            return redirect(url_for('view_scores_by_set'))
        
        # Get set_number from the first answer (all answers should be from the same set for a given score_id)
        set_number = answers[0]['set_number']
        score['set_number'] = set_number
        
        return render_template('view_answers_by_set.html', score=score, answers=answers)
    except Exception as e:
        app.logger.error(f"View answers by set error: {str(e)}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        flash('Error loading answers. Please try again later.', 'danger')
        return redirect(url_for('view_scores_by_set'))
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/view_answers/<int:score_id>')
@login_required
def view_answers(score_id):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                s.candidate_id,
                c.full_name,
                c.email,
                s.score_id,
                s.attempt_number,
                s.total_questions,
                s.correct_answers,
                s.score_percent,
                s.submitted_at
            FROM scores s
            JOIN candidates c ON s.candidate_id = c.candidate_id
            WHERE s.score_id = %s
        """, (score_id,))
        score = cursor.fetchone()
        if not score:
            flash('Score not found.', 'danger')
            return redirect(url_for('view_scores'))
        
        # Fetch questions and answers for this specific score_id
        # All answers linked to this score_id belong to the same attempt and set
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
            ORDER BY q.set_number, q.category, q.question_id
        """, (score_id,))
        answers = cursor.fetchall()
        
        if not answers:
            flash('No answers found for this score.', 'danger')
            return redirect(url_for('view_scores'))
        
        # Get set_number from the first answer (all answers should be from the same set for a given score_id)
        set_number = answers[0]['set_number']
        score['set_number'] = set_number
        
        return render_template('view_answers.html', score=score, answers=answers)
    except Exception as e:
        app.logger.error(f"View answers error: {str(e)}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        flash('Error loading answers. Please try again later.', 'danger')
        return redirect(url_for('view_scores'))
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/monitor_test')
@login_required
def monitor_test():
    conn = None
    try:
        # Check if S3 client is available
        if not s3_client:
            flash('S3 configuration is missing or incomplete. Please configure AWS credentials in your .env file.', 'warning')
            return render_template('monitor_test.html', videos=[])
        
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
                
                # Fetch candidate information for videos that have candidate_id
                candidate_ids = [v['candidate_id'] for v in videos if v['candidate_id']]
                candidate_info_map = {}
                if candidate_ids:
                    conn = get_db_connection()
                    cursor = conn.cursor(dictionary=True)
                    unique_candidate_ids = list(set(candidate_ids))
                    placeholders = ','.join(['%s'] * len(unique_candidate_ids))
                    cursor.execute(f"""
                        SELECT candidate_id, full_name, email
                        FROM candidates
                        WHERE candidate_id IN ({placeholders})
                    """, tuple(unique_candidate_ids))
                    candidate_records = cursor.fetchall()
                    
                    for candidate_record in candidate_records:
                        candidate_info_map[candidate_record['candidate_id']] = {
                            'full_name': candidate_record['full_name'],
                            'email': candidate_record['email']
                        }
                    
                    # Add candidate info to videos
                    for video in videos:
                        if video['candidate_id'] and video['candidate_id'] in candidate_info_map:
                            video['candidate_name'] = candidate_info_map[video['candidate_id']]['full_name']
                            video['candidate_email'] = candidate_info_map[video['candidate_id']]['email']
                        else:
                            video['candidate_name'] = None
                            video['candidate_email'] = None
                    
                    conn.close()
                    conn = None
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            app.logger.error(f"Error fetching videos from S3 - Code: {error_code}, Message: {error_message}")
            app.logger.error(f"Bucket: {S3_BUCKET}, Prefix: {S3_VIDEO_PREFIX}, Region: {S3_REGION}")
            
            if error_code == 'NoSuchBucket':
                flash(f'Error: S3 bucket "{S3_BUCKET}" does not exist. Please check your S3 configuration.', 'danger')
            elif error_code == 'AccessDenied':
                flash('Error: Access denied to S3 bucket. Please check your AWS credentials and permissions.', 'danger')
            elif error_code == 'InvalidAccessKeyId':
                flash('Error: Invalid AWS Access Key ID. Please check your S3 configuration.', 'danger')
            elif error_code == 'SignatureDoesNotMatch':
                flash('Error: Invalid AWS Secret Access Key. Please check your S3 configuration.', 'danger')
            else:
                flash(f'Error fetching videos from S3: {error_message}. Please check your S3 configuration.', 'danger')
        except Exception as e:
            app.logger.error(f"Unexpected error fetching videos: {str(e)}")
            app.logger.error(f"Traceback: {traceback.format_exc()}")
            flash(f'Unexpected error: {str(e)}. Please check the logs for more details.', 'danger')
        
        return render_template('monitor_test.html', videos=videos)
    except Exception as e:
        app.logger.error(f"Monitor test error: {str(e)} with traceback: {traceback.format_exc()}")
        flash('Error loading monitoring page. Please try again later.', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if conn and conn.is_connected():
            conn.close()

@app.route('/view_video/<path:s3_key>')
@login_required
def view_video(s3_key):
    """Generate a signed URL for viewing a video from S3"""
    conn = None
    try:
        # Check if S3 client is available
        if not s3_client:
            flash('S3 configuration is missing. Cannot load video.', 'danger')
            return redirect(url_for('monitor_test'))
        
        # Validate that the key starts with the expected prefix for security
        if not s3_key.startswith(S3_VIDEO_PREFIX):
            flash('Invalid video path.', 'danger')
            return redirect(url_for('monitor_test'))
        
        # Extract filename and parse candidate info
        filename = s3_key.split('/')[-1]
        candidate_id = None
        candidate_name = None
        candidate_email = None
        
        # Parse candidate ID from filename
        # Format: candidate{candidate_id}attempt{attempt_number}{timestamp}.webm
        if filename.startswith('candidate') and 'attempt' in filename:
            try:
                parts = filename.replace('.webm', '').split('attempt')
                if len(parts) == 2:
                    candidate_id_str = parts[0].replace('candidate', '')
                    candidate_id = int(candidate_id_str) if candidate_id_str.isdigit() else None
            except (ValueError, IndexError):
                pass
        
        # Fetch candidate information from database
        if candidate_id:
            try:
                conn = get_db_connection()
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT candidate_id, full_name, email
                    FROM candidates
                    WHERE candidate_id = %s
                """, (candidate_id,))
                candidate_record = cursor.fetchone()
                if candidate_record:
                    candidate_name = candidate_record['full_name']
                    candidate_email = candidate_record['email']
            except Exception as e:
                app.logger.error(f"Error fetching candidate info: {str(e)}")
            finally:
                if conn and conn.is_connected():
                    conn.close()
        
        # Generate a presigned URL that expires in 1 hour
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': S3_BUCKET,
                'Key': s3_key
            },
            ExpiresIn=3600  # 1 hour
        )
        
        return render_template('view_video.html', 
                             video_url=presigned_url, 
                             filename=filename,
                             candidate_id=candidate_id,
                             candidate_name=candidate_name,
                             candidate_email=candidate_email)
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        app.logger.error(f"Error generating presigned URL - Code: {error_code}, Message: {error_message}")
        flash(f'Error loading video: {error_message}', 'danger')
        return redirect(url_for('monitor_test'))
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
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

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    """Add a new admin user"""
    conn = None
    cursor = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('add_user.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('add_user.html')
        
        if len(username) > 50:
            flash('Username must be 50 characters or less.', 'danger')
            return render_template('add_user.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('add_user.html')
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Check if username already exists
            cursor.execute("SELECT id FROM admin_users WHERE username = %s", (username,))
            if cursor.fetchone():
                flash('Username already exists. Please choose a different username.', 'danger')
                return render_template('add_user.html')
            
            # Hash the password
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            # Insert new user
            cursor.execute(
                "INSERT INTO admin_users (username, password_hash) VALUES (%s, %s)",
                (username, password_hash.decode('utf-8'))
            )
            conn.commit()
            
            flash(f'User "{username}" has been added successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            app.logger.error(f"Add user error: {str(e)}")
            app.logger.error(f"Traceback: {traceback.format_exc()}")
            if conn:
                conn.rollback()
            flash('Error adding user. Please try again later.', 'danger')
            return render_template('add_user.html')
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()
    
    return render_template('add_user.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/view_tab_switches')
@login_required
def view_tab_switches():
    """View tab switch monitoring data for all candidates"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # First check if table exists
        cursor.execute("SHOW TABLES LIKE 'tab_switches'")
        if not cursor.fetchone():
            flash('Tab switches table does not exist. Please create it first.', 'warning')
            return render_template('tab_switches.html', switches=[], candidate_stats=[])
        
        # Get tab switch data with candidate information using actual table structure
        # Columns: id, candidate_id, attempt_number, switch_out_count, updated_at
        # Use LEFT JOIN to handle cases where candidate_id might not match
        cursor.execute("""
            SELECT 
                ts.id,
                ts.candidate_id,
                ts.attempt_number,
                COALESCE(ts.switch_out_count, 0) AS switch_out_count,
                ts.updated_at,
                c.full_name,
                c.email
            FROM tab_switches ts
            LEFT JOIN candidates c ON ts.candidate_id = c.candidate_id
            WHERE ts.candidate_id IS NOT NULL
            ORDER BY ts.updated_at DESC, ts.id DESC
        """)
        switches = cursor.fetchall()
        
        # Aggregate switch counts by candidate using candidate_id column
        # Use LEFT JOIN and handle NULL values
        cursor.execute("""
            SELECT 
                ts.candidate_id,
                COALESCE(c.full_name, 'Unknown') AS full_name,
                COALESCE(c.email, 'N/A') AS email,
                COUNT(DISTINCT ts.attempt_number) AS total_attempts,
                COALESCE(SUM(ts.switch_out_count), 0) AS total_switch_outs,
                COUNT(*) AS total_records,
                MAX(ts.updated_at) AS last_switch_time
            FROM tab_switches ts
            LEFT JOIN candidates c ON ts.candidate_id = c.candidate_id
            WHERE ts.candidate_id IS NOT NULL
            GROUP BY ts.candidate_id, c.full_name, c.email
            HAVING total_records > 0
            ORDER BY total_switch_outs DESC, last_switch_time DESC
        """)
        candidate_stats = cursor.fetchall()
        
        return render_template('tab_switches.html', 
                             switches=switches, 
                             candidate_stats=candidate_stats)
    except Exception as e:
        app.logger.error(f"View tab switches error: {str(e)}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        flash(f'Error loading tab switch data: {str(e)}. Please check the logs for details.', 'danger')
        # Return empty data instead of redirecting so user can see the page structure
        return render_template('tab_switches.html', switches=[], candidate_stats=[])
    finally:
        if conn and conn.is_connected():
            conn.close()

@app.route('/test')
@login_required
def test():
    return "Admin app is working!"

if __name__ == '__main__':
    print("Starting Flask Admin Application on port 5001...")
    socketio.run(app, debug=True, host='0.0.0.0', port=5001)