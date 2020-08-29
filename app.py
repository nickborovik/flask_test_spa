from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from passlib.hash import sha256_crypt

engine = create_engine('mysql+pymysql://root:123456@localhost/register')
db = scoped_session(sessionmaker(bind=engine))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'somethingverysecret'


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        fullname = request.form.get('fullname')
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        secure_password = sha256_crypt.encrypt(str(password))

        if password == confirm:
            db.execute('INSERT INTO users(fullname, email, password) '
                       'VALUES(:fullname, :email, :password)',
                       {'fullname': fullname, 'email': email, 'password': secure_password})
            db.commit()
            flash('You are registered and can login', 'success')
            return redirect(url_for('login'))

        flash('Password does not match', 'danger')
        return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        email_data = db.execute('SELECT email FROM users WHERE email=:email',
                               {'email': email}).fetchone()
        password_data = db.execute('SELECT password FROM users WHERE email=:email',
                                  {'email': email}).fetchone()
        fullname = db.execute('SELECT fullname FROM users WHERE email=:email',
                                  {'email': email}).fetchone()

        if email_data is None:
            flash('Wrong email, try again', 'danger')
            return render_template('login.html')
        if sha256_crypt.verify(password, password_data[0]):
            session['email'] = email_data[0]
            session['fullname'] = fullname[0]
            flash('You are now logged in', 'success')
            return redirect(url_for('profile'))
        flash('Incorrect password', 'danger')
        return render_template('login.html')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('email', None)
    flash('You are now logged out', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'email' in session:
        return render_template('profile.html')
    else:
        flash('You need to log in to see this page', 'danger')
        return redirect(url_for('login'))


if __name__ == '__main__':
    app.run()
