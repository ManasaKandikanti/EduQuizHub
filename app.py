from flask import Flask, render_template, request, redirect, session, url_for
from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Database connection
def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

# Home page
@app.route("/")
def home():
    return render_template("home.html")

# Login page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if not user:
            flash("Email not registered. Please register first.", "warning")
            return redirect(url_for("login"))
        elif not check_password_hash(user["password"], password):
            flash("Incorrect password. Try again.", "danger")
            return redirect(url_for("login"))
        else:
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['name']}!", "success")
            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("student_dashboard"))

    return render_template("login.html")


# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # or your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'manasakandikanti0410@gmail.com'  # sender email
app.config['MAIL_PASSWORD'] = 'gvoz zzdf nifg zbpi'  # app password
mail = Mail(app)

def send_otp_email(to_email, otp):
    msg = Message('EduQuizHub Registration OTP',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[to_email])
    msg.body = f'Your OTP for registration is: {otp}'
    mail.send(msg)


# Register page
import re

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        # Password regex validation
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(pattern, password):
            flash("Password must be minimum 8 characters, include uppercase, lowercase, number and special character.", "danger")
            return redirect(url_for("register"))

        # Check if email already exists
        conn = get_db_connection()
        existing_user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if existing_user:
            flash("Email already registered. Try logging in.", "warning")
            conn.close()
            return redirect(url_for("register"))
        
        # Generate OTP
        import random
        otp = random.randint(100000, 999999)
        session['otp'] = otp
        session['reg_name'] = name
        session['reg_email'] = email
        session['reg_password'] = generate_password_hash(password)

        # Send OTP email
        send_otp_email(email, otp)
        conn.close()

        flash("OTP sent to your email. Please verify.", "info")
        return redirect(url_for("verify_otp"))

    return render_template("register.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        user_otp = request.form["otp"]
        if str(user_otp) == str(session.get("otp")):
            # Save user to DB
            conn = get_db_connection()
            conn.execute("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
                         (session['reg_name'], session['reg_email'], session['reg_password'], 'student'))
            conn.commit()
            conn.close()

            # Clear session variables
            session.pop('otp', None)
            session.pop('reg_name', None)
            session.pop('reg_email', None)
            session.pop('reg_password', None)

            flash("Registration successful! You can now login.", "success")
            return redirect(url_for("login"))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for("verify_otp"))
    return render_template("verify_otp.html")



# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# Admin dashboard
@app.route("/admin-dashboard")
def admin_dashboard():
    if "role" in session and session["role"] == "admin":
        return render_template("admin_dashboard.html")
    return redirect(url_for("login"))

@app.route("/admin/add-module", methods=["GET", "POST"])
def add_module():
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        module_name = request.form["module_name"]
        conn = get_db_connection()
        conn.execute("INSERT INTO modules (name) VALUES (?)", (module_name,))
        conn.commit()
        conn.close()
        flash("Module added successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_module.html")


@app.route("/admin/add-quiz", methods=["GET", "POST"])
def add_quiz():
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    modules = conn.execute("SELECT * FROM modules").fetchall()

    if request.method == "POST":
        module_id = request.form["module_id"]
        title = request.form["title"]
        time_limit = request.form["time_limit"]
        conn.execute("INSERT INTO quizzes (module_id, title, time_limit) VALUES (?, ?, ?)",
                     (module_id, title, time_limit))
        conn.commit()
        conn.close()
        flash("Quiz added successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    conn.close()
    return render_template("add_quiz.html", modules=modules)


@app.route("/admin/add-questions/<int:quiz_id>", methods=["GET", "POST"])
def add_questions(quiz_id):
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        question = request.form["question"]
        option1 = request.form["option1"]
        option2 = request.form["option2"]
        option3 = request.form["option3"]
        option4 = request.form["option4"]
        correct_option = request.form["correct_option"]

        conn = get_db_connection()
        conn.execute("""INSERT INTO questions 
                        (quiz_id, question, option1, option2, option3, option4, correct_option)
                        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                     (quiz_id, question, option1, option2, option3, option4, correct_option))
        conn.commit()
        conn.close()
        flash("Question added successfully!", "success")
        return redirect(url_for("add_questions", quiz_id=quiz_id))

    return render_template("add_questions.html", quiz_id=quiz_id)

@app.route("/admin/publish-quiz/<int:quiz_id>")
def publish_quiz(quiz_id):
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    conn.execute("UPDATE quizzes SET is_active = 1 WHERE id = ?", (quiz_id,))
    conn.commit()
    conn.close()
    flash("Quiz published successfully!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/select-quiz-for-publish")
def select_quiz_for_publish():
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    quizzes = conn.execute("SELECT * FROM quizzes").fetchall()
    conn.close()
    return render_template("select_quiz.html", quizzes=quizzes, action="publish_quiz")


@app.route("/admin/select-quiz-for-questions")
def select_quiz_for_questions():
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    quizzes = conn.execute("SELECT * FROM quizzes").fetchall()
    conn.close()

    return render_template(
        "select_quiz.html",
        quizzes=quizzes,
        action="add_questions"
    )

@app.route("/admin/select-quiz-for-results")
def select_quiz_for_results():
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    quizzes = conn.execute("SELECT * FROM quizzes").fetchall()
    conn.close()

    return render_template(
        "select_quiz.html",
        quizzes=quizzes,
        action="view_results"
    )

@app.route("/admin/view-results/<int:quiz_id>")
def view_results(quiz_id):
    conn = get_db_connection()

    quiz = conn.execute(
        "SELECT * FROM quizzes WHERE id = ?",
        (quiz_id,)
    ).fetchone()

    results = conn.execute("""
        SELECT
            u.name AS student_name,
            q.title AS quiz_title,
            a.score,
            a.total_questions
        FROM attempts a
        JOIN users u ON a.student_id = u.id
        JOIN quizzes q ON a.quiz_id = q.id
        WHERE a.quiz_id = ?
    """, (quiz_id,)).fetchall()

    conn.close()
    return render_template(
        "admin_results.html",
        results=results,
        quiz=quiz
    )




@app.route("/admin/modules")
def manage_modules():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db_connection()
    modules = conn.execute("SELECT * FROM modules").fetchall()
    conn.close()

    return render_template("manage_modules.html", modules=modules)

@app.route("/admin/module/<int:module_id>/quizzes")
def module_quizzes_admin(module_id):
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db_connection()
    quizzes = conn.execute("""
        SELECT * FROM quizzes WHERE module_id = ?
    """, (module_id,)).fetchall()
    conn.close()

    return render_template(
        "admin_module_quizzes.html",
        quizzes=quizzes,
        module_id=module_id
    )

@app.route("/admin/results")
def admin_results():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db_connection()
    results = conn.execute("""
        SELECT users.name AS student,
               modules.name AS module,
               quizzes.title AS quiz,
               attempts.score,
               attempts.total_questions
        FROM attempts
        JOIN users ON attempts.student_id = users.id
        JOIN quizzes ON attempts.quiz_id = quizzes.id
        JOIN modules ON quizzes.module_id = modules.id
        ORDER BY quizzes.id
    """).fetchall()
    conn.close()

    return render_template("admin_results.html", results=results)


@app.route("/admin/select-module-for-quiz")
def select_module_for_quiz():
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    modules = conn.execute("SELECT * FROM modules").fetchall()
    conn.close()

    return render_template("select_module_for_quiz.html", modules=modules)





# Student dashboard
@app.route("/student-dashboard")
def student_dashboard():
    if "role" in session and session["role"] == "student":
        return render_template("student_dashboard.html")
    return redirect(url_for("login"))


@app.route("/student/modules")
def student_modules():
    if session.get("role") != "student":
        return redirect(url_for("login"))

    conn = get_db_connection()
    modules = conn.execute("SELECT * FROM modules").fetchall()
    conn.close()

    return render_template("student_modules.html", modules=modules)


@app.route("/student/active-quizzes")
def student_active_quizzes():
    if session.get("role") != "student":
        return redirect(url_for("login"))

    conn = get_db_connection()
    quizzes = conn.execute("""
        SELECT quizzes.*, modules.name AS module_name
        FROM quizzes
        JOIN modules ON quizzes.module_id = modules.id
        WHERE quizzes.is_active = 1
    """).fetchall()
    conn.close()

    return render_template("student_quizzes.html", quizzes=quizzes)


@app.route("/student/attempt-quiz/<int:quiz_id>", methods=["GET", "POST"])
def attempt_quiz(quiz_id):
    if session.get("role") != "student":
        return redirect(url_for("login"))

    conn = get_db_connection()

    if request.method == "POST":
        questions = conn.execute(
            "SELECT * FROM questions WHERE quiz_id = ?", (quiz_id,)
        ).fetchall()

        score = 0
        for q in questions:
            selected = request.form.get(str(q["id"]))
            if selected and int(selected) == q["correct_option"]:
                score += 1

        conn.execute("""
            INSERT INTO attempts (student_id, quiz_id, score, total_questions)
            VALUES (?, ?, ?, ?)
        """, (session["user_id"], quiz_id, score, len(questions)))

        conn.commit()
        conn.close()

        flash(f"You scored {score} / {len(questions)}", "success")
        return redirect(url_for("student_results"))

    questions = conn.execute(
        "SELECT * FROM questions WHERE quiz_id = ?", (quiz_id,)
    ).fetchall()
    conn.close()

    return render_template("attempt_quiz.html", questions=questions)

@app.route("/student/results")
def student_results():
    if session.get("role") != "student":
        return redirect(url_for("login"))

    conn = get_db_connection()
    results = conn.execute("""
        SELECT modules.name AS module_name,
               quizzes.title,
               attempts.score,
               attempts.total_questions
        FROM attempts
        JOIN quizzes ON attempts.quiz_id = quizzes.id
        JOIN modules ON quizzes.module_id = modules.id
        WHERE attempts.student_id = ?
    """, (session["user_id"],)).fetchall()
    conn.close()

    return render_template("student_results.html", results=results)



@app.route("/student/module/<int:module_id>/quizzes")
def module_quizzes(module_id):
    if session.get("role") != "student":
        return redirect(url_for("login"))

    conn = get_db_connection()
    quizzes = conn.execute("""
        SELECT * FROM quizzes
        WHERE module_id = ? AND is_active = 1
    """, (module_id,)).fetchall()
    conn.close()

    return render_template("module_quizzes.html", quizzes=quizzes)


if __name__ == "__main__":
    app.run(debug=True)
