# 3-Way Authentication System

This project is a **3-way authentication system** built using Flask and Tailwind CSS. It provides a highly secure authentication mechanism using three layers of verification:

1. **Email and Password Authentication**
2. **Color-Based Authentication**
3. **Email OTP Verification**

## Features

- User Registration with Email and Password
- OTP-based Email Verification during Registration
- Login with Email and Password
- Color Selection for Secondary Authentication
- OTP-based Final Authentication after Color Verification
- Recovery Key Generation and Delivery via Email
- Logout Functionality
- Session Management and Secure Routes

## Technologies Used

### Backend:
- **Flask**: Lightweight Python web framework
- **Flask-Bcrypt**: For password hashing
- **Flask-Mail**: For sending emails
- **PyOTP**: For generating time-based OTPs
- **SQLAlchemy**: Database ORM

### Frontend:
- **Tailwind CSS**: For modern and responsive styling

### Other:
- **SQLite**: Lightweight database for development
- **Python 3**

## Installation

Follow the steps below to set up the project locally:

### Prerequisites:
- Python 3.8 or higher
- Virtual Environment (recommended)

### Steps:

1. **Clone the Repository:**
   ```bash
   git clone <repository-url>
   cd <repository-folder>
   ```

2. **Set Up a Virtual Environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables:**
   Create a `.env` file in the root directory and add the following variables:
   ```env
  class Config:
    
    SECRET_KEY = os.urandom(24)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = ''
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = ''
    MAIL_PASSWORD = ''
    MAIL_DEFAULT_SENDER= ''

   ```

5. **Initialize the Database:**
   ```bash
   flask shell
   >>> from models import db
   >>> db.create_all()
   >>> exit()
   ```

6. **Run the Application:**
   ```bash
   flask run
   ```

7. **Access the Application:**
   Visit [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

## Usage Workflow

### 1. User Registration
- User provides their email, password, and a preferred color.
- A recovery key is generated and saved.
- An OTP is sent to the user's email for verification.

### 2. Email Verification
- The user enters the OTP received in their email.
- Upon successful verification, the user's email is marked as verified.

### 3. Login
- The user logs in using their email and password.
- Upon successful login, the user is prompted to select their pre-defined color.

### 4. Color and OTP Verification
- The user selects their color.
- If the selected color matches, an OTP is sent to the user's email.
- The user enters the OTP to complete authentication and access the dashboard.


## Future Enhancements

- Implement multi-language support.
- Add Two-Factor Authentication (2FA) using Google Authenticator.
- Enhance the dashboard with more features and analytics.
- Add password recovery via recovery key.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes. Ensure that your code follows the project guidelines.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Acknowledgments

- **Flask**: For being a simple yet powerful web framework.
- **Tailwind CSS**: For making UI design a breeze.
- **PyOTP**: For enabling OTP functionality.

---


