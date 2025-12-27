import sqlite3

DB_NAME = "database.db"


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


# ---------- Dashboard Queries ----------

def get_total_modules():
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM modules"
        ).fetchone()[0]


def get_total_quizzes():
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM quizzes"
        ).fetchone()[0]


def get_total_students():
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'student'"
        ).fetchone()[0]


def get_user_by_email(email):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

def create_user(name, email, hashed_password, role="student"):
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
            (name, email, hashed_password, role)
        )
        conn.commit()

def get_student_by_id(user_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()


def get_all_modules():
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM modules"
        ).fetchall()


def get_student_module_performance(user_id):
    with get_db_connection() as conn:
        modules = conn.execute("SELECT id, name FROM modules").fetchall()

        module_labels = []
        module_scores = []

        for m in modules:
            attempts = conn.execute("""
                SELECT a.score, a.total_questions
                FROM attempts a
                JOIN quizzes q ON a.quiz_id = q.id
                WHERE a.student_id = ? AND q.module_id = ?
            """, (user_id, m["id"])).fetchall()

            total_score = sum(a["score"] for a in attempts)
            total_questions = sum(a["total_questions"] for a in attempts)

            percent = round(
                (total_score / total_questions) * 100, 2
            ) if total_questions else 0

            module_labels.append(m["name"])
            module_scores.append(percent)

        return module_labels, module_scores

def get_user_by_id(user_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()


def update_user_profile(user_id, name, email, profile_image):
    with get_db_connection() as conn:
        conn.execute(
            "UPDATE users SET name = ?, email = ?, profile_image = ? WHERE id = ?",
            (name, email, profile_image, user_id)
        )
        conn.commit()


def update_user_name_email(user_id, name, email):
    with get_db_connection() as conn:
        conn.execute(
            "UPDATE users SET name = ?, email = ? WHERE id = ?",
            (name, email, user_id)
        )
        conn.commit()

def create_module(module_name):
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO modules (name) VALUES (?)",
            (module_name,)
        )
        conn.commit()

def get_module_by_id(module_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM modules WHERE id = ?",
            (module_id,)
        ).fetchone()


def create_quiz(module_id, title, time_limit):
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO quizzes (module_id, title, time_limit) VALUES (?, ?, ?)",
            (module_id, title, time_limit)
        )
        conn.commit()

def create_question(
    quiz_id,
    question,
    option1,
    option2,
    option3,
    option4,
    correct_option
):
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO questions
            (quiz_id, question, option1, option2, option3, option4, correct_option)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                quiz_id,
                question,
                option1,
                option2,
                option3,
                option4,
                correct_option
            )
        )
        conn.commit()

def quiz_has_questions(quiz_id):
    with get_db_connection() as conn:
        questions = conn.execute(
            "SELECT 1 FROM questions WHERE quiz_id = ? LIMIT 1",
            (quiz_id,)
        ).fetchone()
        return questions is not None


def publish_quiz_by_id(quiz_id):
    with get_db_connection() as conn:
        conn.execute(
            "UPDATE quizzes SET is_active = 1 WHERE id = ?",
            (quiz_id,)
        )
        conn.commit()

def get_all_quizzes():
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM quizzes"
        ).fetchall()

def get_quizzes_with_module_names():
    with get_db_connection() as conn:
        return conn.execute(
            """
            SELECT quizzes.*, modules.name AS module_name
            FROM quizzes
            JOIN modules ON quizzes.module_id = modules.id
            ORDER BY modules.name, quizzes.title
            """
        ).fetchall()

def get_quiz_by_id(quiz_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM quizzes WHERE id = ?",
            (quiz_id,)
        ).fetchone()


def get_quiz_results(quiz_id):
    with get_db_connection() as conn:
        return conn.execute(
            """
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
            """,
            (quiz_id,)
        ).fetchall()

def get_quizzes_by_module(module_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM quizzes WHERE module_id = ?",
            (module_id,)
        ).fetchall()


def get_module_by_id(module_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM modules WHERE id = ?",
            (module_id,)
        ).fetchone()

def get_questions_by_quiz(quiz_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM questions WHERE quiz_id = ?",
            (quiz_id,)
        ).fetchall()

def get_question_by_id(question_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM questions WHERE id = ?",
            (question_id,)
        ).fetchone()


def update_question(
    question_id,
    question_text,
    option1,
    option2,
    option3,
    option4,
    correct_option
):
    with get_db_connection() as conn:
        conn.execute(
            """
            UPDATE questions
            SET question = ?, option1 = ?, option2 = ?, option3 = ?, option4 = ?, correct_option = ?
            WHERE id = ?
            """,
            (question_text, option1, option2, option3, option4, correct_option, question_id)
        )
        conn.commit()

def get_quiz_id_by_question(question_id):
    with get_db_connection() as conn:
        result = conn.execute(
            "SELECT quiz_id FROM questions WHERE id = ?",
            (question_id,)
        ).fetchone()
        return result["quiz_id"] if result else None


def delete_question_by_id(question_id):
    with get_db_connection() as conn:
        conn.execute(
            "DELETE FROM questions WHERE id = ?",
            (question_id,)
        )
        conn.commit()

def get_all_results():
    with get_db_connection() as conn:
        return conn.execute(
            """
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
            """
        ).fetchall()

def get_student_by_id(user_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()


def get_all_modules():
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM modules"
        ).fetchall()


def get_student_attempts_by_module(user_id, module_id):
    with get_db_connection() as conn:
        return conn.execute(
            """
            SELECT a.score, a.total_questions
            FROM attempts a
            JOIN quizzes q ON a.quiz_id = q.id
            WHERE a.student_id = ? AND q.module_id = ?
            """,
            (user_id, module_id)
        ).fetchall()


def get_student_attempt_count_by_module(user_id, module_id):
    with get_db_connection() as conn:
        result = conn.execute(
            """
            SELECT COUNT(*) as cnt
            FROM attempts a
            JOIN quizzes q ON a.quiz_id = q.id
            WHERE a.student_id = ? AND q.module_id = ?
            """,
            (user_id, module_id)
        ).fetchone()
        return result['cnt'] if result else 0

def get_active_quizzes_with_module_names():
    with get_db_connection() as conn:
        return conn.execute(
            """
            SELECT quizzes.*, modules.name AS module_name
            FROM quizzes
            JOIN modules ON quizzes.module_id = modules.id
            WHERE quizzes.is_active = 1
            """
        ).fetchall()

def get_quiz_by_id(quiz_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM quizzes WHERE id = ?",
            (quiz_id,)
        ).fetchone()


def get_questions_by_quiz(quiz_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM questions WHERE quiz_id = ?",
            (quiz_id,)
        ).fetchall()

def get_latest_attempt(student_id, quiz_id):
    with get_db_connection() as conn:
        return conn.execute(
            """
            SELECT * FROM attempts
            WHERE student_id = ? AND quiz_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (student_id, quiz_id)
        ).fetchone()


def get_questions_by_quiz(quiz_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM questions WHERE quiz_id = ?",
            (quiz_id,)
        ).fetchall()

import json

def get_questions_by_quiz(quiz_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM questions WHERE quiz_id = ?",
            (quiz_id,)
        ).fetchall()


def save_quiz_attempt(student_id, quiz_id, score, total_questions, answers_dict):
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO attempts (student_id, quiz_id, score, total_questions, answers)
            VALUES (?, ?, ?, ?, ?)
            """,
            (student_id, quiz_id, score, total_questions, json.dumps(answers_dict))
        )
        conn.commit()

def get_student_results(student_id):
    with get_db_connection() as conn:
        return conn.execute(
            """
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
            """,
            (student_id, student_id)
        ).fetchall()

def get_student_module_quizzes(student_id, module_id):
    with get_db_connection() as conn:
        return conn.execute(
            """
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
            """,
            (student_id, module_id)
        ).fetchall()

def get_all_students():
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE role = 'student'"
        ).fetchall()

def delete_student_attempts(student_id):
    with get_db_connection() as conn:
        conn.execute(
            "DELETE FROM attempts WHERE student_id = ?",
            (student_id,)
        )
        conn.commit()


def delete_student_by_id(student_id):
    with get_db_connection() as conn:
        conn.execute(
            "DELETE FROM users WHERE id = ?",
            (student_id,)
        )
        conn.commit()

def get_student_by_id(student_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (student_id,)
        ).fetchone()


def get_student_attempts(student_id):
    with get_db_connection() as conn:
        return conn.execute(
            """
            SELECT m.name AS module_name,
                   q.title AS quiz_title,
                   a.score,
                   a.total_questions
            FROM attempts a
            JOIN quizzes q ON a.quiz_id = q.id
            JOIN modules m ON q.module_id = m.id
            WHERE a.student_id = ?
            ORDER BY m.name, q.title
            """,
            (student_id,)
        ).fetchall()

def get_admin_user():
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE role='admin'"
        ).fetchone()


def get_total_modules():
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM modules"
        ).fetchone()[0]


def get_total_quizzes():
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM quizzes"
        ).fetchone()[0]


def get_total_active_quizzes():
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM quizzes WHERE is_active=1"
        ).fetchone()[0]


def get_total_students():
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM users WHERE role='student'"
        ).fetchone()[0]

def get_all_modules():
    with get_db_connection() as conn:
        return conn.execute("SELECT * FROM modules").fetchall()


def get_module_avg_score(module_name):
    with get_db_connection() as conn:
        avg = conn.execute("""
            SELECT AVG(a.score*100.0/a.total_questions)
            FROM attempts a
            JOIN quizzes q ON a.quiz_id = q.id
            JOIN modules m ON q.module_id = m.id
            WHERE m.name=?
        """, (module_name,)).fetchone()[0]
        return round(avg or 0, 2)


def get_all_quizzes():
    with get_db_connection() as conn:
        return conn.execute("SELECT * FROM quizzes").fetchall()


def get_quiz_attempt_count(quiz_id):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE quiz_id=?", (quiz_id,)
        ).fetchone()[0]


def get_quiz_avg_score(quiz_title):
    with get_db_connection() as conn:
        avg = conn.execute("""
            SELECT AVG(score*100.0/total_questions)
            FROM attempts a
            JOIN quizzes q ON a.quiz_id = q.id
            WHERE q.title=?
        """, (quiz_title,)).fetchone()[0]
        return round(avg or 0, 2)
