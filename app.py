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
    conn = get_db_connection()

    total_modules = conn.execute("SELECT COUNT(*) FROM modules").fetchone()[0]
    total_quizzes = conn.execute("SELECT COUNT(*) FROM quizzes").fetchone()[0]
    total_students = conn.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'student'"
    ).fetchone()[0]

    conn.close()

    return render_template(
        "home.html",
        total_modules=total_modules,
        total_quizzes=total_quizzes,
        total_students=total_students
    )


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

    module_id = request.args.get("module_id")

    conn = get_db_connection()
    module = None

    if module_id:
        module = conn.execute(
            "SELECT * FROM modules WHERE id = ?",
            (module_id,)
        ).fetchone()

    if request.method == "POST":
        module_id = request.form["module_id"]
        title = request.form["title"]
        time_limit = request.form["time_limit"]

        conn.execute(
            "INSERT INTO quizzes (module_id, title, time_limit) VALUES (?, ?, ?)",
            (module_id, title, time_limit)
        )
        conn.commit()
        conn.close()

        flash("Quiz added successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    conn.close()
    return render_template("add_quiz.html", module=module)



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
    # Join quizzes with modules to get module name
    quizzes = conn.execute("""
        SELECT quizzes.*, modules.name AS module_name
        FROM quizzes
        JOIN modules ON quizzes.module_id = modules.id
        ORDER BY modules.name, quizzes.title
    """).fetchall()
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
            m.name AS module_name,
            q.title AS quiz_title,
            a.score,
            a.total_questions
        FROM attempts a
        JOIN users u ON a.student_id = u.id
        JOIN quizzes q ON a.quiz_id = q.id
        JOIN modules m ON q.module_id = m.id
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

    quizzes = conn.execute(
        "SELECT * FROM quizzes WHERE module_id = ?",
        (module_id,)
    ).fetchall()

    module = conn.execute(
        "SELECT * FROM modules WHERE id = ?",
        (module_id,)
    ).fetchone()

    conn.close()

    return render_template(
        "admin_module_quizzes.html",
        quizzes=quizzes,
        module=module   # 👈 IMPORTANT
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





@app.route("/student-dashboard")
def student_dashboard():
    if "role" in session and session["role"] == "student":
        user_id = session["user_id"]
        conn = get_db_connection()
        
        # Get student name
        student = conn.execute("SELECT name FROM users WHERE id = ?", (user_id,)).fetchone()
        student_name = student['name'] if student else "Student"

        # Module-wise performance
        modules = conn.execute("SELECT * FROM modules").fetchall()
        module_labels = []
        module_scores = []

        for m in modules:
            attempts = conn.execute("""
                SELECT a.score, a.total_questions
                FROM attempts a
                JOIN quizzes q ON a.quiz_id = q.id
                WHERE a.student_id=? AND q.module_id=?
            """, (user_id, m['id'])).fetchall()

            total_score = sum([a['score'] for a in attempts])
            total_questions = sum([a['total_questions'] for a in attempts])
            percent = round((total_score / total_questions * 100), 2) if total_questions else 0

            module_labels.append(m['name'])
            module_scores.append(percent)

        # Total modules completed (number of quizzes attempted per module)
        module_totals = []
        for m in modules:
            count = conn.execute("""
                SELECT COUNT(*) as cnt
                FROM attempts a
                JOIN quizzes q ON a.quiz_id = q.id
                WHERE a.student_id=? AND q.module_id=?
            """, (user_id, m['id'])).fetchone()['cnt']
            module_totals.append(count)

        conn.close()

        return render_template(
            "student_dashboard.html",
            student_name=student_name,
            module_labels=module_labels,
            module_scores=module_scores,
            module_totals=module_totals
        )
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
    quiz = conn.execute("SELECT * FROM quizzes WHERE id = ?", (quiz_id,)).fetchone()
    questions = conn.execute("SELECT * FROM questions WHERE quiz_id = ?", (quiz_id,)).fetchall()
    conn.close()

    return render_template("attempt_quiz.html", quiz=quiz, questions=questions)


import json

import json  # make sure this is imported

@app.route("/student/quiz-result/<int:quiz_id>")
def quiz_result(quiz_id):
    if session.get("role") != "student":
        return redirect(url_for("login"))

    conn = get_db_connection()
    quiz = conn.execute("SELECT * FROM quizzes WHERE id = ?", (quiz_id,)).fetchone()
    attempts = conn.execute("""
        SELECT * FROM attempts 
        WHERE student_id=? AND quiz_id=?
        ORDER BY id DESC LIMIT 1
    """, (session["user_id"], quiz_id)).fetchone()

    questions = conn.execute("SELECT * FROM questions WHERE quiz_id=?", (quiz_id,)).fetchall()
    conn.close()

    # Parse the answers JSON in Python
    attempts_answers = json.loads(attempts["answers"]) if attempts and attempts["answers"] else {}

    return render_template(
        "quiz_result.html",
        quiz=quiz,
        attempts=attempts,
        questions=questions,
        attempts_answers=attempts_answers  # pass to template
    )


import json

@app.route("/student/submit-quiz/<int:quiz_id>", methods=["POST"])
def submit_quiz(quiz_id):
    if session.get("role") != "student":
        return redirect(url_for("login"))

    conn = get_db_connection()
    questions = conn.execute("SELECT * FROM questions WHERE quiz_id = ?", (quiz_id,)).fetchall()

    score = 0
    answers = {}
    for q in questions:
        user_ans = request.form.get(str(q["id"]))
        if user_ans:
            user_ans = int(user_ans)
            answers[q["id"]] = user_ans
            if user_ans == q["correct_option"]:
                score += 1
        else:
            answers[q["id"]] = None  # mark unanswered

    # Save attempt with answers JSON
    conn.execute("""
        INSERT INTO attempts (student_id, quiz_id, score, total_questions, answers)
        VALUES (?, ?, ?, ?, ?)
    """, (session["user_id"], quiz_id, score, len(questions), json.dumps(answers)))
    conn.commit()
    conn.close()

    return redirect(url_for("quiz_result", quiz_id=quiz_id))



@app.route("/student/results")
def student_results():
    if session.get("role") != "student":
        return redirect(url_for("login"))

    conn = get_db_connection()
    results = conn.execute("""
    SELECT modules.name AS module_name,
           quizzes.title,
           attempts.score,
           attempts.total_questions,
           COUNT(a2.id) AS attempt_count
    FROM attempts
    JOIN quizzes ON attempts.quiz_id = quizzes.id
    JOIN modules ON quizzes.module_id = modules.id
    LEFT JOIN attempts a2 ON a2.quiz_id = quizzes.id AND a2.student_id = ?
    WHERE attempts.student_id = ?
    GROUP BY quizzes.id
""", (session["user_id"], session["user_id"])).fetchall()
    conn.close()

    return render_template("student_results.html", results=results)



@app.route("/student/module/<int:module_id>/quizzes")
def module_quizzes(module_id):
    if session.get("role") != "student":
        return redirect(url_for("login"))

    conn = get_db_connection()
    quizzes = conn.execute("""
        SELECT q.*,
               IFNULL(a.attempt_count, 0) AS attempt_count,
               IFNULL(a.percentage, 0) AS last_percentage
        FROM quizzes q
        LEFT JOIN (
            SELECT quiz_id,
                   COUNT(*) AS attempt_count,
                   ROUND(MAX(score*100.0/total_questions), 2) AS percentage
            FROM attempts
            WHERE student_id = ?
            GROUP BY quiz_id
        ) a ON q.id = a.quiz_id
        WHERE q.module_id = ? AND q.is_active = 1
    """, (session["user_id"], module_id)).fetchall()
    conn.close()

    return render_template("module_quizzes.html", quizzes=quizzes)


@app.route("/admin/students")
def admin_students():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db_connection()
    students = conn.execute("SELECT * FROM users WHERE role = 'student'").fetchall()
    conn.close()
    return render_template("admin_students.html", students=students)

@app.route("/admin/student/<int:student_id>")
def admin_student_detail(student_id):
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db_connection()
    student = conn.execute("SELECT * FROM users WHERE id = ?", (student_id,)).fetchone()

    quizzes = conn.execute("""
        SELECT m.name AS module_name,
               q.title AS quiz_title,
               a.score,
               a.total_questions
        FROM attempts a
        JOIN quizzes q ON a.quiz_id = q.id
        JOIN modules m ON q.module_id = m.id
        WHERE a.student_id = ?
        ORDER BY m.name, q.title
    """, (student_id,)).fetchall()

    # Calculate totals and overall percentage
    total_score = sum(q['score'] for q in quizzes)
    total_possible_score = sum(q['total_questions'] for q in quizzes)
    overall_percentage = round((total_score / total_possible_score * 100) if total_possible_score else 0, 2)

    # Module-wise chart
    modules_dict = {}
    for q in quizzes:
        if q['module_name'] not in modules_dict:
            modules_dict[q['module_name']] = []
        modules_dict[q['module_name']].append((q['score'], q['total_questions']))

    modules_labels = []
    modules_scores = []
    for module, scores in modules_dict.items():
        modules_labels.append(module)
        avg = round(sum(s[0] for s in scores) / sum(s[1] for s in scores) * 100, 2) if scores else 0
        modules_scores.append(avg)

    quizzes_labels = [q['quiz_title'] for q in quizzes]
    quizzes_scores = [round(q['score'] / q['total_questions'] * 100, 2) if q['total_questions'] else 0 for q in quizzes]

    conn.close()

    return render_template(
        "admin_student_detail.html",
        student=student,
        quizzes=quizzes,
        total_quizzes=len(quizzes),
        total_score=total_score,
        total_possible_score=total_possible_score,
        overall_percentage=overall_percentage,
        modules_labels=modules_labels,
        modules_scores=modules_scores,
        quizzes_labels=quizzes_labels,
        quizzes_scores=quizzes_scores
    )


@app.route("/admin/info")
def admin_info():
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    admin = conn.execute("SELECT * FROM users WHERE role='admin'").fetchone()
    total_modules = conn.execute("SELECT COUNT(*) FROM modules").fetchone()[0]
    total_quizzes = conn.execute("SELECT COUNT(*) FROM quizzes").fetchone()[0]
    total_active_quizzes = conn.execute("SELECT COUNT(*) FROM quizzes WHERE is_active=1").fetchone()[0]
    total_students = conn.execute("SELECT COUNT(*) FROM users WHERE role='student'").fetchone()[0]
    conn.close()

    return render_template(
        "admin_info.html",
        admin=admin,
        total_modules=total_modules,
        total_quizzes=total_quizzes,
        total_active_quizzes=total_active_quizzes,
        total_students=total_students
    )

@app.route("/admin/statistics")
def admin_statistics():
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()

    # Chart data
    modules_labels = [m['name'] for m in conn.execute("SELECT * FROM modules").fetchall()]
    modules_scores = []
    for m in modules_labels:
        avg = conn.execute("""
            SELECT AVG(a.score*100.0/a.total_questions)
            FROM attempts a
            JOIN quizzes q ON a.quiz_id = q.id
            JOIN modules m ON q.module_id = m.id
            WHERE m.name=?
        """, (m,)).fetchone()[0] or 0
        modules_scores.append(round(avg,2))

    quizzes_labels = [q['title'] for q in conn.execute("SELECT * FROM quizzes").fetchall()]
    quizzes_attempts = [conn.execute("SELECT COUNT(*) FROM attempts WHERE quiz_id=?", (i+1,)).fetchone()[0] for i in range(len(quizzes_labels))]
    quizzes_avg_scores = []
    for i, q in enumerate(quizzes_labels):
        avg = conn.execute("SELECT AVG(score*100.0/total_questions) FROM attempts a JOIN quizzes q ON a.quiz_id=q.id WHERE q.title=?", (q,)).fetchone()[0] or 0
        quizzes_avg_scores.append(round(avg,2))

    conn.close()

    return render_template("admin_statistics.html",
                           modules_labels=modules_labels,
                           modules_scores=modules_scores,
                           quizzes_labels=quizzes_labels,
                           quizzes_attempts=quizzes_attempts,
                           quizzes_avg_scores=quizzes_avg_scores)


if __name__ == "__main__":
    app.run(debug=True)
