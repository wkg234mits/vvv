from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_mail import Mail, Message
from apscheduler.schedulers.background import BackgroundScheduler

# Configuration de l'application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'olfa2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/fuelguard'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'hachmibarhoumi52@gmail.com'
app.config['MAIL_PASSWORD'] = 'PWD'

# Initialisation des extensions
db = SQLAlchemy(app)
mail = Mail(app)
scheduler = BackgroundScheduler()

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Modèles
class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    volume = db.Column(db.Float)
    is_alert = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    truck_id = db.Column(db.Integer, db.ForeignKey('truck.id'))
    truck = db.relationship('Truck', backref='alerts')

    
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(20))
    tasks = db.relationship('Task', backref='user', lazy=True)

class Truck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    model = db.Column(db.String(100))
    matricule = db.Column(db.String(20), unique=True)
    fuel_level = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    tasks = db.relationship('Task', backref='truck', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    driver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    truck_id = db.Column(db.Integer, db.ForeignKey('truck.id'))
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    status = db.Column(db.String(20))
    lieu_depart = db.Column(db.String(100))
    lieu_arrivee = db.Column(db.String(100))
    

class FuelHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    truck_id = db.Column(db.Integer, db.ForeignKey('truck.id'))
    fuel_level = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Context Processor
@app.context_processor
def inject_global_data():
    def get_low_fuel_count():
        return Truck.query.filter(Truck.fuel_level <= 20).count()
    return dict(low_fuel_count=get_low_fuel_count(), current_year=datetime.now().year)

# Login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Notification carburant


# Authentification
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Adresse e-mail incorrecte.', 'danger')
        elif not check_password_hash(user.password, password):
            flash('Mot de passe incorrect.', 'danger')
        else:
            login_user(user)
            return redirect(url_for('admin_dashboard' if user.role == 'admin' else 'driver_dashboard'))
    
    return render_template('auth/login.html')


# Déconnexion
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Vous avez été déconnecté avec succès.", "info")
    return redirect(url_for('login'))






@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    trucks = Truck.query.all()
    users = User.query.filter_by(role='driver').all()
    admins = User.query.filter_by(role='admin').all()  
    active_tasks = Task.query.filter(Task.status != 'Terminé').count()

    return render_template('admin/dashboard.html',
                           trucks=trucks,
                           users=users,
                           admins=admins,
                           active_tasks=active_tasks)

# Variable globale pour stocker le volume reçu


@app.route('/admin/alerts')
@login_required
def view_alerts():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    # Afficher uniquement les alertes <= 100 ml
    alerts = Alert.query.filter(Alert.volume <= 100).order_by(Alert.timestamp.desc()).all()
    return render_template('admin/alerts.html', alerts=alerts)

@app.route('/admin/alerts/delete_all', methods=['POST'])
@login_required
def delete_all_alerts():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    try:
        Alert.query.delete()
        db.session.commit()
        flash("Toutes les alertes ont été supprimées avec succès.", "success")
    except Exception as e:
        db.session.rollback()
        flash("Erreur lors de la suppression des alertes.", "danger")

    return redirect(url_for('view_alerts'))


@app.route('/admin/trucks')
@login_required
def manage_trucks():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    return render_template('admin/manage_trucks.html', trucks=Truck.query.all())

@app.route('/add_truck', methods=['POST'])
@login_required
def add_truck():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    truck = Truck(model=request.form['model'], matricule=request.form['matricule'], fuel_level=request.form['fuel_level'])
    db.session.add(truck)
    db.session.commit()
    flash('Camion ajouté avec succès', 'success')
    return redirect(url_for('manage_trucks'))

@app.route('/edit_truck/<int:truck_id>', methods=['POST'])
@login_required
def edit_truck(truck_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    truck = Truck.query.get_or_404(truck_id)
    truck.model = request.form['model']
    truck.matricule = request.form['matricule']
    truck.fuel_level = request.form['fuel_level']
    db.session.commit()
    flash('Camion modifié avec succès', 'success')
    return redirect(url_for('manage_trucks'))

@app.route('/delete_truck/<int:truck_id>', methods=['POST'])
@login_required
def delete_truck(truck_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    db.session.delete(Truck.query.get_or_404(truck_id))
    db.session.commit()
    flash('Camion supprimé avec succès', 'success')
    return redirect(url_for('manage_trucks'))

@app.route('/admin/users')
@login_required
def manage_users():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    return render_template('admin/manage_users.html', users=User.query.all())

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    email = request.form['email']
    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        flash('Erreur : un utilisateur avec cet email existe déjà.', 'danger')
        return redirect(url_for('manage_users'))

    user = User(email=email,
                password=generate_password_hash(request.form['password']),
                role=request.form['role'])
    
    db.session.add(user)
    db.session.commit()
    flash('Utilisateur créé avec succès', 'success')
    return redirect(url_for('manage_users'))


@app.route('/edit_user/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    user.email = request.form['email']
    user.role = request.form['role']
    db.session.commit()
    flash('Utilisateur modifié avec succès', 'success')
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    db.session.delete(User.query.get_or_404(user_id))
    db.session.commit()
    flash('Utilisateur supprimé avec succès', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/tasks')
@login_required
def manage_tasks():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    return render_template('admin/manage_tasks.html',
                           tasks=Task.query.all(),
                           users=User.query.filter_by(role='driver').all(),
                           trucks=Truck.query.all(),volume=volume_data)
volume_data = 0
ALERT_THRESHOLD = 100  # ml

@app.route('/data', methods=['POST'])
def receive_data():
    global volume_data
    volume = request.form.get('volume')

    if volume:
        volume_data = float(volume)

        # Créer une nouvelle alerte
        is_alert = volume_data <= ALERT_THRESHOLD
        alert = Alert(volume=volume_data, is_alert=is_alert)
        db.session.add(alert)
        db.session.commit()

        # Envoyer l'email si volume critique
        if is_alert:
            try:
                msg = Message("Alerte carburant - FuelGuard",
                              sender="hachmibarhoumi52@gmail.com",
                              recipients=["hachmibarhoumi52@gmail.com"])
                msg.body = f"Alerte : Niveau de carburant critique détecté ({volume_data} ml)."
                mail.send(msg)
            except Exception as e:
                print("Erreur envoi email :", e)

        return "OK", 200
    return "Missing data", 400
@app.route('/assign_task', methods=['POST'])
@login_required
def assign_task():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    task = Task(
        driver_id=request.form['driver_id'],
        truck_id=request.form['truck_id'],
        start_date=datetime.strptime(request.form['start_date'], '%Y-%m-%dT%H:%M'),
        end_date=datetime.strptime(request.form['end_date'], '%Y-%m-%dT%H:%M'),
        lieu_depart=request.form['lieu_depart'],
        lieu_arrivee=request.form['lieu_arrivee'],
        status='En cours'
    )
    db.session.add(task)
    db.session.commit()
    flash('Tâche assignée avec succès', 'success')
    return redirect(url_for('manage_tasks'))

@app.route('/delete_task/<int:task_id>', methods=['DELETE'])
@login_required
def delete_task(task_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    db.session.delete(Task.query.get_or_404(task_id))
    db.session.commit()
    return jsonify({'message': 'Tâche supprimée avec succès'}), 200

@app.route('/driver/dashboard')
@login_required
def driver_dashboard():
    if current_user.role != 'driver':
        return redirect(url_for('login'))
    return render_template('driver/dashboard.html',
                           current_task=Task.query.filter_by(driver_id=current_user.id, status='En cours').first())

@app.route('/driver/tasks')
@login_required
def driver_tasks():
    if current_user.role != 'driver':
        return redirect(url_for('login'))
    return render_template('driver/tasks.html',
                           tasks=Task.query.filter_by(driver_id=current_user.id).all())

@app.route('/update_fuel', methods=['POST'])
@login_required
def update_fuel():
    if current_user.role != 'driver':
        flash('Accès refusé', 'danger')
        return redirect(url_for('login'))

    task = Task.query.get(request.form.get('task_id'))
    if not task or task.driver_id != current_user.id:
        flash('Tâche non trouvée ou non autorisée', 'danger')
        return redirect(url_for('driver_dashboard'))

    truck = Truck.query.get(task.truck_id)
    try:
        new_level = float(request.form.get('fuel_level'))
    except (ValueError, TypeError):
        flash('Valeur de carburant invalide', 'danger')
        return redirect(url_for('driver_dashboard'))


    flash('Niveau de carburant mis à jour avec succès', 'success')
    return redirect(url_for('driver_dashboard'))

# Création de la base + admin
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='admin@cpg.tn').first():
        db.session.add(User(
            email='admin@cpg.tn',
            password=generate_password_hash('cpg2025'),
            role='admin'
        ))
        db.session.commit()

# Lancement de l'application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True,host='0.0.0.0', port=5000)

