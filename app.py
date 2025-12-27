from flask import Flask, render_template, request, redirect, session, url_for
from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = "supersecretkey"

from db.db import (
    get_total_modules,
    get_total_quizzes,
    get_total_students,
    get_user_by_email,
    create_user,
    get_student_by_id,
    get_student_module_performance,
    update_user_name_email,
    update_user_profile,
    get_user_by_id,
    create_module,
    create_quiz,
    get_module_by_id,
    create_question,
    quiz_has_questions,
    publish_quiz_by_id,
    get_all_quizzes,
    get_quizzes_with_module_names,
    get_quiz_by_id,
    get_quiz_results,
    get_all_modules,
    get_quizzes_by_module,
    get_questions_by_quiz,
    get_question_by_id,
    update_question,
    get_quiz_id_by_question,
    delete_question_by_id,
    get_all_results,
    get_student_attempts_by_module,
    get_student_attempt_count_by_module,
    get_active_quizzes_with_module_names,
    get_latest_attempt,
    get_questions_by_quiz, 
    save_quiz_attempt,
    get_student_results,
    get_student_module_quizzes,
    get_all_students,
    delete_student_attempts,
    delete_student_by_id,
    get_student_attempts,
    get_admin_user,
    get_total_active_quizzes,
    get_module_avg_score,
    get_quiz_attempt_count,
    get_quiz_avg_score,
)

# Home page
@app.route("/")
def home():

    total_modules = get_total_modules()
    total_quizzes = get_total_quizzes()
    total_students = get_total_students()

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

        user = get_user_by_email(email)

        if not user:
            flash("Email not registered. Please register first.", "warning")
            return redirect(url_for("login"))

        if not check_password_hash(user["password"], password):
            flash("Incorrect password. Try again.", "danger")
            return redirect(url_for("login"))

        # Login success
        session["user_id"] = user["id"]
        session["role"] = user["role"]

        flash(f"Welcome back, {user['name']}!", "success")

        if user["role"] == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("student_dashboard"))

    return render_template("login.html")


from flask_mail import Mail, Message

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'manasakandikanti0410@gmail.com'
app.config['MAIL_PASSWORD'] = 'gvoz zzdf nifg zbpi'

mail = Mail(app)

def send_otp_email(to_email, otp):
    msg = Message(
        'EduQuizHub Registration OTP',
        sender=app.config['MAIL_USERNAME'],
        recipients=[to_email]
    )
    msg.body = f'Your OTP for registration is: {otp}'
    mail.send(msg)


import re,random 

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        # Password validation
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(pattern, password):
            flash(
                "Password must be minimum 8 characters, include uppercase, lowercase, number and special character.",
                "danger"
            )
            return redirect(url_for("register"))

        # Check email
        if get_user_by_email(email):
            flash("Email already registered. Try logging in.", "warning")
            return redirect(url_for("register"))

        # Generate OTP
        otp = random.randint(100000, 999999)

        session['otp'] = otp
        session['reg_name'] = name
        session['reg_email'] = email
        session['reg_password'] = generate_password_hash(password)

        send_otp_email(email, otp)

        flash("OTP sent to your email. Please verify.", "info")
        return redirect(url_for("verify_otp"))

    return render_template("register.html")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        user_otp = request.form["otp"]

        if str(user_otp) != str(session.get("otp")):
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for("verify_otp"))

        # Save user
        create_user(
            session['reg_name'],
            session['reg_email'],
            session['reg_password']
        )

        # Clear session
        session.pop('otp', None)
        session.pop('reg_name', None)
        session.pop('reg_email', None)
        session.pop('reg_password', None)

        flash("Registration successful! You can now login.", "success")
        return redirect(url_for("login"))

    return render_template("verify_otp.html")


@app.route("/student/profile")
def student_profile():
    if session.get("role") != "student":
        return redirect(url_for("login"))

    user_id = session["user_id"]

    student = get_student_by_id(user_id)
    module_labels, module_scores = get_student_module_performance(user_id)

    return render_template(
        "student_profile.html",
        student=student,
        module_labels=module_labels,
        module_scores=module_scores
    )

from werkzeug.utils import secure_filename
import os
import time

UPLOAD_FOLDER = "static/images/profiles"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/student/edit-profile", methods=["GET", "POST"])
def edit_profile():
    if session.get("role") != "student":
        return redirect(url_for("login"))

    user_id = session["user_id"]
    student = get_user_by_id(user_id)

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]

        file = request.files.get("profile_image")

        if file and allowed_file(file.filename):
            timestamp = int(time.time())
            filename = f"{timestamp}_{secure_filename(file.filename)}"
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            profile_image = filename
        else:
            profile_image = student["profile_image"] or "default.png"

        update_user_profile(user_id, name, email, profile_image)

        flash("Profile updated successfully!", "success")
        return redirect(url_for("student_profile"))

    return render_template("edit_profile.html", student=student)

@app.route("/student/verify-otp-update", methods=["GET", "POST"])
def verify_otp_update():
    if session.get("role") != "student":
        return redirect(url_for("login"))

    if request.method == "POST":
        user_otp = request.form["otp"]

        if str(user_otp) != str(session.get("otp")):
            flash("Invalid OTP. Try again.", "danger")
            return redirect(url_for("verify_otp_update"))

        update_user_name_email(
            session["user_id"],
            session["new_name"],
            session["new_email"]
        )

        session.pop("otp", None)
        session.pop("new_name", None)
        session.pop("new_email", None)

        flash("Profile updated successfully!", "success")
        return redirect(url_for("student_profile"))

    return render_template("verify_otp_update.html")

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

        create_module(module_name)

        flash("Module added successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_module.html")


@app.route("/admin/add-quiz", methods=["GET", "POST"])
def add_quiz():
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    module_id = request.args.get("module_id")
    module = get_module_by_id(module_id) if module_id else None

    if request.method == "POST":
        module_id = request.form["module_id"]
        title = request.form["title"]
        time_limit = request.form["time_limit"]

        create_quiz(module_id, title, time_limit)

        flash("Quiz added successfully!", "success")
        return redirect(url_for("admin_dashboard"))

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

        create_question(
            quiz_id,
            question,
            option1,
            option2,
            option3,
            option4,
            correct_option
        )

        flash("Question added successfully!", "success")
        return redirect(url_for("add_questions", quiz_id=quiz_id))

    return render_template("add_questions.html", quiz_id=quiz_id)

# Admin publishes a quiz
@app.route("/admin/publish-quiz/<int:quiz_id>")
def publish_quiz(quiz_id):
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    if not quiz_has_questions(quiz_id):
        flash("Cannot publish quiz without any questions.", "warning")
        return redirect(url_for("view_quiz_questions", quiz_id=quiz_id))

    publish_quiz_by_id(quiz_id)

    flash("Quiz published successfully!", "success")
    return redirect(url_for("admin_dashboard"))

# Admin selects a quiz to publish
@app.route("/admin/select-quiz-for-publish")
def select_quiz_for_publish():
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    quizzes = get_all_quizzes()

    return render_template(
        "select_quiz.html",
        quizzes=quizzes,
        action="publish_quiz"
    )

@app.route("/admin/select-quiz-for-questions")
def select_quiz_for_questions():
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    quizzes = get_all_quizzes()

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

    quizzes = get_quizzes_with_module_names()

    return render_template(
        "select_quiz.html",
        quizzes=quizzes,
        action="view_results"
    )


@app.route("/admin/view-results/<int:quiz_id>")
def view_results(quiz_id):
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    quiz = get_quiz_by_id(quiz_id)
    results = get_quiz_results(quiz_id)

    return render_template(
        "admin_results.html",
        results=results,
        quiz=quiz
    )


@app.route("/admin/modules")
def manage_modules():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    modules = get_all_modules()

    return render_template(
        "manage_modules.html",
        modules=modules
    )

@app.route("/admin/module/<int:module_id>/quizzes")
def module_quizzes_admin(module_id):
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    quizzes = get_quizzes_by_module(module_id)
    module = get_module_by_id(module_id)

    return render_template(
        "admin_module_quizzes.html",
        quizzes=quizzes,
        module=module  
    )

@app.route("/admin/view-questions/<int:quiz_id>")
def view_quiz_questions(quiz_id):
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    quiz = get_quiz_by_id(quiz_id)
    questions = get_questions_by_quiz(quiz_id)

    return render_template(
        "view_questions.html",
        quiz=quiz,
        questions=questions
    )

@app.route("/admin/edit-question/<int:question_id>", methods=["GET", "POST"])
def edit_question(question_id):
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    question = get_question_by_id(question_id)

    if request.method == "POST":
        q_text = request.form["question"]
        option1 = request.form["option1"]
        option2 = request.form["option2"]
        option3 = request.form["option3"]
        option4 = request.form["option4"]
        correct_option = int(request.form["correct_option"])

        update_question(
            question_id,
            q_text,
            option1,
            option2,
            option3,
            option4,
            correct_option
        )

        flash("Question updated successfully!", "success")
        return redirect(url_for("view_quiz_questions", quiz_id=question["quiz_id"]))

    return render_template("edit_question.html", question=question)


@app.route("/admin/delete-question/<int:question_id>")
def delete_question(question_id):
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    quiz_id = get_quiz_id_by_question(question_id)
    if quiz_id is None:
        flash("Question not found!", "danger")
        return redirect(url_for("admin_dashboard"))

    delete_question_by_id(question_id)
    flash("Question deleted successfully!", "success")
    return redirect(url_for("view_quiz_questions", quiz_id=quiz_id))


@app.route("/admin/results")
def admin_results():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    results = get_all_results()

    return render_template(
        "admin_results.html",
        results=results
    )

@app.route("/admin/select-module-for-quiz")
def select_module_for_quiz():
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    modules = get_all_modules()

    return render_template(
        "select_module_for_quiz.html",
        modules=modules
    )


@app.route("/student-dashboard")
def student_dashboard():
    if session.get("role") != "student":
        return redirect(url_for("login"))

    user_id = session["user_id"]
    student = get_student_by_id(user_id)
    modules = get_all_modules()

    module_labels = []
    module_scores = []
    module_totals = []

    for m in modules:
        attempts = get_student_attempts_by_module(user_id, m['id'])
        total_score = sum(a['score'] for a in attempts)
        total_questions = sum(a['total_questions'] for a in attempts)
        percent = round((total_score / total_questions * 100), 2) if total_questions else 0

        module_labels.append(m['name'])
        module_scores.append(percent)
        module_totals.append(get_student_attempt_count_by_module(user_id, m['id']))

    return render_template(
        "student_dashboard.html",
        student=student,
        module_labels=module_labels,
        module_scores=module_scores,
        module_totals=module_totals
    )


@app.route("/student/modules")
def student_modules():
    if session.get("role") != "student":
        return redirect(url_for("login"))

    modules = get_all_modules()

    return render_template(
        "student_modules.html",
        modules=modules
    )


@app.route("/student/active-quizzes")
def student_active_quizzes():
    if session.get("role") != "student":
        return redirect(url_for("login"))

    quizzes = get_active_quizzes_with_module_names()

    return render_template(
        "student_quizzes.html",
        quizzes=quizzes
    )


@app.route("/student/attempt-quiz/<int:quiz_id>", methods=["GET", "POST"])
def attempt_quiz(quiz_id):
    if session.get("role") != "student":
        return redirect(url_for("login"))

    quiz = get_quiz_by_id(quiz_id)
    questions = get_questions_by_quiz(quiz_id)

    return render_template(
        "attempt_quiz.html",
        quiz=quiz,
        questions=questions
    )


import json

@app.route("/student/quiz-result/<int:quiz_id>")
def quiz_result(quiz_id):
    if session.get("role") != "student":
        return redirect(url_for("login"))

    quiz = get_quiz_by_id(quiz_id)
    attempts = get_latest_attempt(session["user_id"], quiz_id)
    questions = get_questions_by_quiz(quiz_id)

    # Parse the answers JSON in Python
    attempts_answers = json.loads(attempts["answers"]) if attempts and attempts["answers"] else {}

    return render_template(
        "quiz_result.html",
        quiz=quiz,
        attempts=attempts,
        questions=questions,
        attempts_answers=attempts_answers
    )


@app.route("/student/submit-quiz/<int:quiz_id>", methods=["POST"])
def submit_quiz(quiz_id):
    if session.get("role") != "student":
        return redirect(url_for("login"))

    questions = get_questions_by_quiz(quiz_id)

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

    save_quiz_attempt(
        student_id=session["user_id"],
        quiz_id=quiz_id,
        score=score,
        total_questions=len(questions),
        answers_dict=answers
    )

    return redirect(url_for("quiz_result", quiz_id=quiz_id))



@app.route("/student/results")
def student_results():
    if session.get("role") != "student":
        return redirect(url_for("login"))

    results = get_student_results(session["user_id"])

    return render_template(
        "student_results.html",
        results=results
    )


@app.route("/student/module/<int:module_id>/quizzes")
def module_quizzes(module_id):
    if session.get("role") != "student":
        return redirect(url_for("login"))

    quizzes = get_student_module_quizzes(session["user_id"], module_id)

    return render_template(
        "module_quizzes.html",
        quizzes=quizzes
    )

@app.route("/admin/students")
def admin_students():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    students = get_all_students()

    return render_template(
        "admin_students.html",
        students=students
    )

@app.route("/admin/delete-student/<int:student_id>", methods=["POST"])
def delete_student(student_id):
    if session.get("role") != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("login"))

    # Delete all attempts first
    delete_student_attempts(student_id)
    # Delete student
    delete_student_by_id(student_id)

    flash("Student and their quiz attempts deleted successfully!", "success")
    return redirect(url_for("admin_students"))


@app.route("/admin/student/<int:student_id>")
def admin_student_detail(student_id):
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    student = get_student_by_id(student_id)
    quizzes = get_student_attempts(student_id)

    # Calculate totals and overall percentage
    total_score = sum(q['score'] for q in quizzes)
    total_possible_score = sum(q['total_questions'] for q in quizzes)
    overall_percentage = round((total_score / total_possible_score * 100) if total_possible_score else 0, 2)

    # Module-wise chart
    modules_dict = {}
    for q in quizzes:
        modules_dict.setdefault(q['module_name'], []).append((q['score'], q['total_questions']))

    modules_labels = []
    modules_scores = []
    for module, scores in modules_dict.items():
        modules_labels.append(module)
        avg = round(sum(s[0] for s in scores) / sum(s[1] for s in scores) * 100, 2) if scores else 0
        modules_scores.append(avg)

    quizzes_labels = [q['quiz_title'] for q in quizzes]
    quizzes_scores = [
        round(q['score'] / q['total_questions'] * 100, 2) if q['total_questions'] else 0
        for q in quizzes
    ]

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

    admin = get_admin_user()
    total_modules = get_total_modules()
    total_quizzes = get_total_quizzes()
    total_active_quizzes = get_total_active_quizzes()
    total_students = get_total_students()

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

    # Module chart
    modules = get_all_modules()
    modules_labels = [m['name'] for m in modules]
    modules_scores = [get_module_avg_score(m) for m in modules_labels]

    # Quiz chart
    quizzes = get_all_quizzes()
    quizzes_labels = [q['title'] for q in quizzes]
    quizzes_attempts = [get_quiz_attempt_count(q['id']) for q in quizzes]
    quizzes_avg_scores = [get_quiz_avg_score(q) for q in quizzes_labels]

    return render_template(
        "admin_statistics.html",
        modules_labels=modules_labels,
        modules_scores=modules_scores,
        quizzes_labels=quizzes_labels,
        quizzes_attempts=quizzes_attempts,
        quizzes_avg_scores=quizzes_avg_scores
    )


if __name__ == "__main__":
    app.run(debug=True)
