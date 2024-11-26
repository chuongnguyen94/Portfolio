from flask import Flask, render_template, redirect, url_for, flash, abort, request, send_from_directory
from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm
from flask_ckeditor import CKEditor, CKEditorField
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
from functools import wraps
from wtforms import StringField, PasswordField, SubmitField, EmailField, TextAreaField
from wtforms.validators import DataRequired, URL
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Text
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date
import smtplib, string, random, os, time, csv, pandas
import undetected_chromedriver as uc
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager


from openai import OpenAI


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
Bootstrap5(app)
ckeditor = CKEditor(app)

#CONFIGURE GRAVATAR
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

#IELTS-BRO SCRAPPING
class Field:
    def __init__(self, field, topics):
        self.field = field
        self.topics = topics
def web_scrapping():
    topics = []
    # driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()))
    # driver = webdriver.Chrome("/Users/cnn/Desktop/untitled folder/Workspace/Python/Chuong-portfolio/chromedriver")
    # driver = webdriver.Chrome()  # Optional argument, if not specified will search path.

    options = webdriver.ChromeOptions()
    options.binary_location = "/usr/bin/google-chrome"
    driver = uc.Chrome(version_main=130)


    # driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager(version="90.0.4430.24").install()))

    driver.get('https://next.ieltsbro.com/forecast/')
    time.sleep(2)
    sections = driver.find_elements(By.CLASS_NAME, 'adm-tabs-tab-wrapper')

    for section in sections:
        # Reading section
        if section.text == '口语':
            section.click()
            for _ in range(5):
                footer = driver.find_element(By.CLASS_NAME, 'adm-infinite-scroll')
                footer.click()
                time.sleep(3)
            fields = driver.find_elements(By.CLASS_NAME, 'sc-hknPuZ')
            for field in fields:
                field.click()
            time.sleep(1)
            result = driver.find_elements(By.CLASS_NAME, 'kzAlbd')
            for each in result:
                topics.append(each.text)
            driver.quit()
    return topics


OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
client = OpenAI(
        api_key=OPENAI_API_KEY)

def chatgpt(prompt):
    stream = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"{prompt}. Use some of the WH-questions to give me some ideas to answer, list out 2 sections: one section is WH-questions and some sugguestions in phrases and words; another section is 3 examples answered the question, each example has 4-6 sentences. Add each line into a <p> HTML tag, title should have tag <h5>, bold the WH-questions."}],
        stream=False,
    )
    return stream.choices[0].message.content


#SEND-EMAIL CONTACT
def send_email(name, email, subject, message):
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=EMAIL, password=PASSWORD)
        connection.sendmail(from_addr=EMAIL, to_addrs='chuongnguyen94@gmail.com', msg=f"Subject: {subject}\n\nHey! You have received an email.\nSender: {name}\nEmail: {email}\nMessage: {message}")

EMAIL = os.environ.get('EMAIL')
PASSWORD = os.environ.get('PASSWORD')

#SEND NEW PASSWORD
def send_new_password(name, email, password):
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=EMAIL, password=PASSWORD)
        connection.sendmail(from_addr=EMAIL, to_addrs=email, msg=f"Subject: Reset your password\n\nHey {name}! This is your new password. Please keep it secret!\nYour new password is: {password}")


#ADMIN ONLY DECORATOR
def admin_only(f):
    @wraps(f)
    def wrapper_function(*args, **kwargs):
        if not current_user.id == 1:
            abort(403)
        return f(*args, **kwargs)
    return wrapper_function

#CONFIGURE FLASK-LOGIN
login_manager = LoginManager()
login_manager.init_app(app)

#CREATE USER_LOADER CALLBACKS
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI",'sqlite:///blog.db')
db = SQLAlchemy(model_class=Base)
db.init_app(app)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    post = relationship('BlogPost', back_populates='author')
    comment = relationship("Comment", back_populates='author_comment')

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="post")

    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    date: Mapped[str] = mapped_column(String(100), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comment = relationship("Comment", back_populates="parent_post")

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    comment: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author_comment = relationship("User", back_populates="comment")

    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comment")

class SpeakingEnglish(db.Model):
    __tablename__ = "speaking"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    topic: Mapped[str] = mapped_column(String(300), nullable=False)
    solution: Mapped[str] = mapped_column(Text, nullable=False)

with app.app_context():
    db.create_all()
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField("Log In")

class ForgotPasswordForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    submit = SubmitField("Reset password")

class ChangePasswordForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')

class CreateUserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign Up")

class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class CommentForm(FlaskForm):
    comment = TextAreaField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")

class ContactForm(FlaskForm):
    name = StringField("Your Name", validators=[DataRequired()])
    email = StringField("Your Email", validators=[DataRequired()])
    subject = StringField("Subject", validators=[DataRequired()])
    message = TextAreaField("Message", validators=[DataRequired()])
    send = SubmitField("Send Message")

class TopicForm(FlaskForm):
    question = StringField("Question", validators=[DataRequired()])
    solution = CKEditorField("Solutions", validators=[DataRequired()])
    submit = SubmitField("Submit Topic")

class GenerateButton(FlaskForm):
    generate = SubmitField('Generate Data')

class GetChatGPTButton(FlaskForm):
    get = SubmitField('Get ChatGPT')

class WriteToDBButton(FlaskForm):
    write = SubmitField("Write To Database")

@app.route('/')
def home():
    return render_template('index.html', current_user=current_user)

@app.route('/about')
def about():
    return redirect('/#about')

@app.route('/skills')
def skills():
    return redirect('/#skills')

@app.route('/resume')
def resume():
    return redirect('/#resume')

@app.route('/download-resume')
def download_resume():
    if not current_user.is_authenticated:
        flash('You need to login to download my CV :)')
        return redirect(url_for('login'))
    return send_from_directory('static', path='assets/files/ChuongCV-Dec.pdf')

@app.route('/portfolio')
def portfolio():
    return redirect('/#portfolio')

@app.route('/publications')
def publications():
    return redirect('/#publications')

@app.route('/contact')
def contact():
    return redirect('/#contact')


@app.route('/product1')
def product1():
    return render_template('product1.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if not current_user.is_authenticated:
        form = LoginForm()
        if form.validate_on_submit():
            email = form.email.data
            user = db.session.execute(db.select(User).where(User.email == email)).scalar()
            if user:
                if(check_password_hash(user.password, form.password.data)):
                    login_user(user)
                    print(current_user.is_authenticated)
                    return redirect(url_for('home'))
                else:
                    flash("Wrong password, please try again.")
                    return redirect(url_for('login'))
            else:
                flash("Email does not exist. Please try again or register new account.")
                return redirect(url_for("register"))
        return render_template('login.html', form=form, current_user=current_user, is_not_home=True)
    else:
        return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if not current_user.is_authenticated:
        form = CreateUserForm()
        if form.validate_on_submit():
            email = form.email.data
            user = db.session.execute(db.select(User).where(User.email == email)).scalar()
            if user:
                flash("Email already exist. Please log in instead.")
                return redirect(url_for('login'))
            else:
                password = generate_password_hash(
                    password=form.password.data,
                    method="pbkdf2",
                    salt_length=8
                )
                new_user = User(
                    name=form.name.data,
                    email=form.email.data,
                    password=password
                )
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for('login'))
        return render_template('register.html', form=form, is_not_home=True, current_user=current_user)
    else:
        return redirect(url_for('home'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
        if user:
            random_password = ''.join(random.choices(string.ascii_letters, k=7))
            password = generate_password_hash(
                password=random_password,
                method="pbkdf2",
                salt_length=8
            )
            user.password = password
            db.session.commit()
            send_new_password(user.name, user.email, random_password)
            flash(f'New password has been sent to {user.email}')
            return redirect(url_for('login'))
        else:
            flash(f"Cannot find email {form.email.data}.")
            return redirect(url_for('forgot_password'))
    return render_template('forgot-password.html', form=form, current_user=current_user)

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if current_user.is_authenticated:
        form = ChangePasswordForm()
        if form.validate_on_submit():
            user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
            if user:
                password = generate_password_hash(
                    password=form.new_password.data,
                    method="pbkdf2",
                    salt_length=8
                )
                user.password = password
                db.session.commit()
                logout_user()
                flash('Password changed successfully. Please log in again.')
                return redirect(url_for('login'))
            else:
                flash(f'Cannot find email {form.email.data}')
                return redirect(url_for('change_password'))
        return render_template('change-password.html', form=form, current_user=current_user)
    else:
        return redirect(url_for('home'))

@app.route('/blog')
def show_all_posts():
    all_posts = db.session.execute(db.select(BlogPost)).scalars()
    return render_template('blog.html', current_user=current_user, posts=all_posts, is_not_home=True)

@app.route('/post<int:post_id>', methods=['GET', 'POST'])
def post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    all_comments = db.session.execute(db.select(Comment)).scalars()
    form=CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('You need to login to comment.')
            return redirect(url_for('login'))
        else:
            comment = Comment(
                comment=form.comment.data,
                author_comment=current_user,
                parent_post=requested_post,
            )
            db.session.add(comment)
            db.session.commit()
            return redirect(url_for('post', post_id=post_id))
    return render_template('post.html', form=form, current_user=current_user, post=requested_post, is_not_home=True, comments=all_comments)

@app.route('/create-post', methods=['GET', 'POST'])
@login_required
@admin_only
def create_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            date=date.today().strftime("%B %d, %Y"),
            author=current_user,
            img_url=form.img_url.data,
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('show_all_posts'))
    return render_template('create-post.html', form=form)

@app.route('/delete<int:post_id>')
@login_required
@admin_only
def delete(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    db.session.delete(requested_post)
    db.session.commit()
    return redirect(url_for('show_all_posts'))

@app.route('/edit-post<int:post_id>', methods=["GET", "POST"])
@admin_only
def edit(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    edit_post = CreatePostForm(
        title=requested_post.title,
        subtitle=requested_post.subtitle,
        img_url=requested_post.img_url,
        body=requested_post.body,
    )
    if edit_post.validate_on_submit():
        requested_post.title = edit_post.title.data
        requested_post.subtitle = edit_post.subtitle.data
        requested_post.img_url = edit_post.img_url.data
        requested_post.body = edit_post.body.data
        db.session.commit()
        return redirect(url_for('show_all_posts'))
    return render_template('create-post.html', post=requested_post, form=edit_post, is_edit=True, is_not_home=True)

@app.route('/edit-resume')
def edit_resume():
    return render_template('create-resume.html', current_user=current_user)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/send-message', methods=['GET', "POST"])
def send_message():
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message'].encode("UTF-8")
        send_email(name, email, subject, message)
        return render_template('index.html', )
    return render_template('index.html', current_user=current_user)

class Topic:
    def __init__(self, topic, solution):
        self.topic = topic
        self.solution = solution
@app.route('/resources', methods=['GET', 'POST'])
def resources():
    topic_data = db.session.execute(db.select(SpeakingEnglish)).scalars()
    generate_data = GenerateButton()
    if generate_data.validate_on_submit():
        topics_bank = web_scrapping()
        with open('static/assets/files/speaking-part-one.csv', 'a', newline='') as data_file:
            writer = csv.writer(data_file)
            writer.writerow(topics_bank)
        return redirect(url_for('write_to_csv'))
    return render_template('resources.html', generate_button=generate_data, topics=topic_data, current_user=current_user)

@app.route('/delete_topic<int:topic_id>')
@login_required
@admin_only
def delete_topic(topic_id):
    requested_topic = db.get_or_404(SpeakingEnglish, topic_id)
    db.session.delete(requested_topic)
    db.session.commit()
    return redirect(url_for('resources'))

@app.route('/write-to-csv', methods=['GET','POST'])
@admin_only
def write_to_csv():
    get_chat_gpt = GetChatGPTButton()
    topics_list = []
    file = pandas.read_csv('static/assets/files/speaking-part-one.csv').to_dict()
    for each in file:
        topics_list.append(each)
    if get_chat_gpt.validate_on_submit():
        topics = []
        solutions = []
        for topic in topics_list[:2]:
            solution = chatgpt(topic)
            topics.append(topic)
            solutions.append(solution)

            #Write solutions to CSV
            data_dict = {
                "topic": topics,
                "solution": solutions
            }
            pandas.DataFrame(data_dict).to_csv('static/assets/files/solution-speaking-part-one.csv', index=False)
        return redirect(url_for('write_to_db'))
    return render_template('write-to-csv.html', current_user=current_user, get_chat_button=get_chat_gpt, list=topics_list)

@app.route('/write-to-db', methods=['GET','POST'])
@admin_only
def write_to_db():
    form = WriteToDBButton()
    # Read solutions from CSV
    data_to_db = pandas.read_csv('static/assets/files/solution-speaking-part-one.csv').to_dict(orient='records')
    if form.validate_on_submit():
        if not data_to_db == []:
            for obj in data_to_db:
                print(obj['topic'])
                new_record = SpeakingEnglish(
                    topic=obj['topic'],
                    solution=obj['solution'],
                )
                db.session.add(new_record)
                db.session.commit()
        return redirect(url_for('resources'))
    return render_template('write-to-db.html', form=form, current_user=current_user)
@app.route('/resources-part-1-<int:topic_id>')
def resource_detail(topic_id):
    requested_topic = db.get_or_404(SpeakingEnglish, topic_id)
    return render_template('resource-detail.html', topic=requested_topic, current_user=current_user)

@app.route('/edit-resource-<int:topic_id>', methods=['GET','POST'])
@admin_only
def edit_resource(topic_id):
    requested_topic = db.get_or_404(SpeakingEnglish, topic_id)
    form = TopicForm(
        question=requested_topic.topic,
        solution=requested_topic.solution,
    )
    if form.validate_on_submit():
        requested_topic.topic = form.question.data
        requested_topic.solution = form.solution.data
        db.session.commit()
        return redirect(url_for('resources'))
    return render_template('create-topic.html', form=form, is_edit=True, topic=requested_topic, current_user=current_user)

if __name__ == "__main__":
    app.run(debug=True)