from flask import Flask, request, jsonify, session, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_redis import FlaskRedis
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import os
import datetime








#app = Flask(_name_)
app = Flask(__name__, static_folder='static')
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
CORS(app)


# Update SQLAlchemy configuration to use Azure SQL Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['REDIS_URL'] = 'redis://localhost:6379/0'  # Redis configuration
db = SQLAlchemy(app)
redis_client = FlaskRedis(app)



# Identity and Access Management Module (IdntyAccMgmtServ)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)




    def _repr_(self):
        return f'<User {self.username}>'





class BandwidthUsage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bandwidth = db.Column(db.Integer, default=0)




# Storage Management Module (StorageMgmtServ)
class Storage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, unique=True, nullable=False)
    used_storage = db.Column(db.Integer, default=0, nullable=False)




# Usage Monitoring Module (UsageMntrServ)
class UsageMonitoring(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, unique=True, nullable=False)
    usage = db.Column(db.Integer, default=0, nullable=False)




# Folder Management Module (FolderMgmtServ)
class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    parent_folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)




    def _repr_(self):
        return f'<Folder {self.name}>'








# File Management Module (FileMgmtServ)
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)
    upload_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)




    def _repr_(self):
        return f'<File {self.name}>'




   
@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=5)




# Create database tables and add initial data
@app.route('/add_initial_data' , methods=['GET', 'POST'])
def add_initial_data():
    with app.app_context():
        # Create tables
        db.create_all()

       
    # Check if users exist; if not, create initial users and data
    # Define initial user data
        initial_users = [
            {'username': 'user1', 'password': 'password1', 'is_admin': False},
            {'username': 'user2', 'password': 'password2', 'is_admin': True},
            # Add more initial user data as needed
        ]




        # Loop through initial user data and create users if they do not exist
        for user_data in initial_users:
            username = user_data['username']
            password = user_data['password']
            is_admin = user_data['is_admin']




            if not User.query.filter_by(username=username).first():
                hashed_password = generate_password_hash(password)
                user = User(username=username, password=hashed_password, is_admin=is_admin)
                db.session.add(user)




                # Create storage entries for the user
                storage = Storage(user_id=user.id, used_storage=1024)  # Initial storage set as needed
                db.session.add(storage)




                # Create usage monitoring entries for the user
                usage = UsageMonitoring(user_id=user.id, usage=512)  # Initial usage set as needed
                db.session.add(usage)




        # Commit changes to the database
        db.session.commit()




    return jsonify({'message': 'Initial data added successfully'}), 201




# Allowed file extensions for documents
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'xlsx', 'jpg', 'jpeg', 'png'}


# Allowed MIME types for images
ALLOWED_IMAGE_TYPES = {'image/jpeg', 'image/png'}


# Function to check if file extension and MIME type are allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def allowed_image_type(mimetype):
    return mimetype in ALLOWED_IMAGE_TYPES




@app.route('/')
def home():
    return 'Hello, World!'




# Route for user signup
@app.route('/signup', methods=['POST'])
def signup():
    username = request.json['username']
    password = request.json['password']


    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'error': 'Username already exists'}), 400

    # Hash the password before storing it
    hashed_password = generate_password_hash(password)

    # Create the user
    user = User(username=username, password=hashed_password)
    db.session.add(user)
    db.session.commit()


    # Initialize storage for the user
    storage = Storage(user_id=user.id, used_storage=0)  # Set initial storage usage as needed
    db.session.add(storage)
    db.session.commit()

    # Get the current storage usage for the user
    user_storage = Storage.query.filter_by(user_id=user.id).first()
    if not user_storage:
        return jsonify({'error': 'Storage data not found'}), 404




    # Get the current bandwidth usage
    global bandwidth  # Assuming bandwidth is a global variable
    bandwidth_usage = bandwidth




    # Prepare the user data to be returned
    user_data = {
        'id': user.id,
        'username': user.username,
        'storage_used': user_storage.used_storage,
        'bandwidth_used': bandwidth_usage
    }




    return jsonify({'message': 'User created successfully', 'user': user_data}), 201



# Define bandwidth as a global variable
bandwidth = 0  # Initial bandwidth set to 0 MB
user_usage = 0  # Initial user usage set to 0 MB






# Route for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid request, please provide username and password'}), 400


    username = data['username']
    password = data['password']


    # Query the user by username
    user = User.query.filter_by(username=username).first()
    

    if user and check_password_hash(user.password, password):
        # Set the user ID in the session
        session.permanent = True  # Make the session permanent (optional)
        session.modified = True  # Make the session permanent (optional)
        session['user_id'] = user.id  # Store the user ID in the session
        # print(f'{session.get('user_id')}, sadsadsad')

        # Get the current storage usage for the user
        user_storage = Storage.query.filter_by(user_id=user.id).first()
        # print(type( user_storage))
        print(user_storage.user_id)
        db.session.commit()
        u= session.get('user_id')
        print(f'{u} session')


        # Check if storage data is not found and create it if necessary
        if not user_storage:
            user_storage = Storage(user_id=user.id, used_storage=0)  # Set initial storage usage as needed
            db.session.add(user_storage)
            # session['user_id']=user.id
            db.session.commit()
            print(user_storage.user_id)
     

        # Get the current bandwidth usage
        global bandwidth  # Assuming bandwidth is a global variable
        bandwidth_usage = bandwidth


        # Prepare the user data to be returned
        user_data = {
            'id': user.id,
            'username': user.username,
            'storage_used': user_storage.used_storage,
            'bandwidth_used': bandwidth_usage
        }


        return jsonify({'user_id': user.id, 'message': 'Login successful', 'user': user_data}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401










# Route for user logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'}), 200




# Route for storage allocation
@app.route('/allocate_storage', methods=['POST'])
def allocate_storage():
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({'error': 'User not logged in'}), 401




    # Check if storage is already allocated for the user
    if redis_client.get(user_id) is not None:
        return jsonify({'error': 'Storage already allocated'}), 400




    # Perform the storage allocation here (e.g., set storage in Redis, update database, etc.)
    # Example:
    redis_client.set(user_id, 10)




    return jsonify({'message': 'Storage allocated successfully'}), 201












# Route for uploading documents
@app.route('/upload_document', methods=['POST'])
def upload_document():
    # Extract user ID from the session
    user_id = session.get('user_id')
   
    # Extract user ID sent from the frontend
    uploaded_user_id = request.form.get('user_id')

    # Check if the user is logged in and the uploaded user ID matches the session user ID
    if user_id is None or user_id != uploaded_user_id:
        return jsonify({'error': 'User not logged in or unauthorized access'}), 401
    
    # Check if a file was included in the request
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400



    file = request.files['file']
   
     # Check if the file has an allowed extension and MIME type
    if file and allowed_file(file.filename) and allowed_image_type(file.mimetype):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        storage = Storage.query.filter_by(user_id=user_id).first()
        if not storage:
            return jsonify({'error': 'Storage not allocated for user'}), 400
        
        file_size = os.path.getsize(file_path)
        if storage.used_storage + file_size > 10 * 1024 * 1024:
            os.remove(file_path)
            return jsonify({'error': 'Storage limit exceeded'}), 400
        
        storage.used_storage += file_size
        db.session.commit()
        
        usage = UsageMonitoring.query.filter_by(user_id=user_id).first()
        if not usage:
            return jsonify({'error': 'Usage data not found'}), 404

        return jsonify({'message': 'Document uploaded successfully', 'usage': usage.usage}), 201
    else:
        return jsonify({'error': 'Invalid file or file type'}), 400











# Usage Monitoring Module (UsageMntrServ)
@app.route('/monitor_usage', methods=['POST'])
def monitor_usage():
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({'error': 'User not logged in'}), 401




    doc_size = request.json['doc_size']
   
    current_usage = int(redis_client.get(user_id + '_usage'))
    if current_usage + doc_size > 25 * 1024 * 1024:
        return jsonify({'error': 'Usage limit exceeded'}), 400
    # Increment the usage in Redis by the document size
    redis_client.incrby(user_id + '_usage', doc_size)
    return jsonify({'message': 'Usage monitored successfully'}), 201








# View Generator Module (ViewGeneratorServ)
@app.route('/view_uploaded_data', methods=['GET'])
def view_uploaded_data():
    # Fetch data from Identity and Access Management module (IdntyAccMgmtServ)
    users = User.query.all()




    # Fetch data from Storage Management module (StorageMgmtServ)
    storage_info = Storage.query.all()




    # Fetch data from Usage Monitoring module (UsageMntrServ)
    usage_info = UsageMonitoring.query.all()




    # Fetch data (files and folders) for the logged-in user
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({'error': 'User not logged in'}), 401




    files = File.query.filter_by(user_id=user_id).all()
    folders = Folder.query.filter_by(user_id=user_id).all()




    # Render the data using the view_data.html template
    return render_template('view_data.html', files=files, folders=folders)








# Admin APIs
@app.route('/admin/create_user', methods=['POST'])
def create_user():
    username = request.json['username']
    password = request.json['password']
    is_admin = request.json.get('is_admin', False)




    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'error': 'Username already exists'}), 400




    hashed_password = generate_password_hash(password)




    user = User(username=username, password=hashed_password, is_admin=is_admin)
    db.session.add(user)
    db.session.commit()




    storage = Storage(user_id=user.id)
    db.session.add(storage)
    db.session.commit()




    return jsonify({'message': 'User created successfully'}), 201




@app.route('/admin/update_user/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    username = request.json.get('username')
    password = request.json.get('password')
    is_admin = request.json.get('is_admin')




    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404




    if username:
        user.username = username
    if password:
        user.password = generate_password_hash(password)
    if is_admin is not None:
        user.is_admin = is_admin




    db.session.commit()




    return jsonify({'message': 'User updated successfully'}), 200




@app.route('/admin/delete_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404




    db.session.delete(user)
    db.session.commit()




    return jsonify({'message': 'User deleted successfully'}), 200




# Dashboard APIs
@app.route('/dashboard/user_info', methods=['GET'])
def get_user_info():
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({'error': 'User not logged in'}), 401




    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404




    return jsonify({'username': user.username, 'is_admin': user.is_admin})




@app.route('/dashboard/storage_info', methods=['GET'])
def get_storage_info():
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({'error': 'User not logged in'}), 401




    storage = Storage.query.filter_by(user_id=user_id).first()
    if not storage:
        return jsonify({'error': 'Storage not allocated for user'}), 404




    return jsonify({'used_storage': storage.used_storage, 'total_storage': storage.total_storage})




@app.route('/dashboard/usage_stats', methods=['GET'])
def get_usage_stats():
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({'error': 'User not logged in'}), 401




    usage = UsageMonitoring.query.filter_by(user_id=user_id).first()
    if not usage:
        return jsonify({'error': 'Usage data not found'}), 404




    return jsonify({'usage': usage.usage})




   




# Run the Flask app
if __name__ == '_main_':




    print("Creating database tables...")
    with app.app_context():
        db.create_all()
    print("Database tables created successfully.")    
    print("Starting Flask application...")
    app.run(debug=True)