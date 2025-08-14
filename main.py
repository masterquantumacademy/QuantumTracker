from flask import Flask, render_template, url_for, flash, redirect, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from wtforms_sqlalchemy.fields import QuerySelectField
import os
import random

basedir = os.path.abspath(os.path.dirname(__file__))

# 1. CONFIGURAÇÃO
app = Flask(__name__)
app.config['SECRET_KEY'] = 'uma-chave-secreta-muito-forte-e-dificil-de-adivinhar'
database_url = os.environ.get('DATABASE_URL')
if database_url:
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url.replace("postgres://", "postgresql://", 1)
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# 2. MODELOS
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    tasks = db.relationship('Task', backref='author', lazy=True)
    categories = db.relationship('Category', backref='author', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    priority = db.Column(db.String(20), nullable=False, default='Foco Secundário') # <-- NOVA LINHA
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tasks = db.relationship('Task', backref='category', lazy=True)

# 3. FORMULÁRIOS
class RegistrationForm(FlaskForm):
    username = StringField('Nome de Usuário', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirmar Senha', validators=[DataRequired(), EqualTo('password', message='As senhas devem ser iguais.')])
    submit = SubmitField('Criar Conta Agora')
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Este nome de usuário já existe.')
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Este e-mail já está em uso.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

def category_query():
    if 'user_id' in session:
        return Category.query.filter_by(author=db.session.get(User, session['user_id']))
    return []

class TaskForm(FlaskForm):
    content = StringField('Nova Meta', validators=[DataRequired()])
    category = QuerySelectField('Categoria', query_factory=category_query, get_label='name', allow_blank=True, blank_text='-- Nenhuma --')
    priority = SelectField('Nível de Foco', choices=['Foco Principal', 'Foco Secundário', 'Intenção Flutuante'], validators=[DataRequired()])
    submit = SubmitField('Adicionar Meta')

class CategoryForm(FlaskForm):
    name = StringField('Nome da Categoria', validators=[DataRequired(), Length(min=2, max=100)])
    submit = SubmitField('Criar Categoria')

# 4. ROTAS
QUANTUM_INSIGHTS = [
    "Sua realidade é um espelho dos seus pensamentos. Pense grande!",
    "Cada meta concluída é um universo de possibilidades que você acaba de criar.",
    "A frequência da gratidão atrai a frequência da abundância.",
    "Você não atrai o que você quer. Você atrai o que você É.",
    "Parabéns! Você colapsou a função de onda da potencialidade para a realidade.",
    "A menor ação é mais poderosa que a maior das intenções.",
]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Falha no login. Verifique o e-mail e a senha.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        # Cria categorias padrão para o novo usuário
        default_categories = ['Carreira', 'Relacionamentos', 'Saúde', 'Espiritualidade']
        for cat_name in default_categories:
            new_cat = Category(name=cat_name, author=user)
            db.session.add(new_cat)
        db.session.commit()
        flash('Sua conta foi criada com sucesso! Você já pode fazer o login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Registrar', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    form = TaskForm()
    
    if form.validate_on_submit():
        task = Task(content=form.content.data, author=user, category=form.category.data, priority=form.priority.data)
        db.session.add(task)
        db.session.commit()
        flash('Sua meta foi materializada!', 'success')
        return redirect(url_for('dashboard'))
    
    # Este bloco precisa estar alinhado com o 'if' acima
    tasks = Task.query.filter_by(author=user).order_by(db.case(
        (Task.priority == 'Foco Principal', 0),
        (Task.priority == 'Foco Secundário', 1),
        (Task.priority == 'Intenção Flutuante', 2),
    ), Task.id.desc()).all()
    
    return render_template('dashboard.html', title='Painel', user=user, form=form, tasks=tasks)
    
@app.route('/categories')
def categories():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    form = CategoryForm()
    user_categories = Category.query.filter_by(author=user).order_by(Category.name).all()
    return render_template('categories.html', title='Gerenciar Categorias', user=user, categories=user_categories, form=form)

@app.route('/categories/add', methods=['POST'])
def add_category():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    form = CategoryForm()
    if form.validate_on_submit():
        user = db.session.get(User, session['user_id'])
        new_cat = Category(name=form.name.data, author=user)
        db.session.add(new_cat)
        db.session.commit()
        flash('Categoria criada com sucesso!', 'success')
    return redirect(url_for('categories'))

@app.route('/categories/delete/<int:category_id>')
def delete_category(category_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    category = Category.query.get_or_404(category_id)
    if category.author.id != session['user_id']:
        return redirect(url_for('dashboard'))
    Task.query.filter_by(category_id=category.id).update({Task.category_id: None})
    db.session.delete(category)
    db.session.commit()
    flash('Categoria apagada.', 'info')
    return redirect(url_for('categories'))

@app.route('/task/toggle/<int:task_id>')
def toggle_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    task = Task.query.get_or_404(task_id)
    if task.author.id != session['user_id']:
        return redirect(url_for('dashboard'))
    task.completed = not task.completed
    if task.completed:
        insight = random.choice(QUANTUM_INSIGHTS)
        flash(insight, 'success')
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/task/delete/<int:task_id>')
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    task = Task.query.get_or_404(task_id)
    if task.author.id != session['user_id']:
        return redirect(url_for('dashboard'))
    db.session.delete(task)
    db.session.commit()
    flash('Sua meta foi desmaterializada com sucesso.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('index'))

# 5. EXECUÇÃO
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)