from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score, classification_report
import re
import nltk
from nltk.corpus import stopwords
import joblib
import os  # To check if files exist

# Download stopwords only the first time
nltk.data.path.append('/var/www/mail_server/nltk_data')
nltk.download('stopwords', download_dir='/var/www/mail_server/nltk_data')
stop_words = set(stopwords.words('english'))

# Optimized text preprocessing
def preprocess_text(text):
    text = text.lower()  # Convert to lowercase
    text = re.sub(r'<.*?>|\d+', '', text)  # Remove HTML tags and digits
    text = re.sub(r'\W+', ' ', text)  # Remove non-alphanumeric characters
    words = [word for word in text.split() if word not in stop_words]
    return " ".join(words)

# Train and save the model if it doesn't exist
def train_model_once():
    if not os.path.exists('best_model_rf.pkl') or not os.path.exists('tfidf_vectorizer.pkl'):
        print("Training the model for the first time...")

        emails = [
        ("Update: Your bank account details", "Please click the link to update your account information.", "spam"),
        ("Congratulations, you've won!", "Click here to claim your $1000 prize.", "spam"),
        ("Reminder: Your account statement", "Please review your account statement.", "not_spam"),
        ("Urgent: Account verification", "Please verify your account information.", "spam"),
        ("Meeting agenda", "Here is the agenda for tomorrow's meeting.", "not_spam"),
        ("Important: Bank Account Locked", "Your bank account has been locked due to suspicious activity. Click here to unlock.", "spam"),
        ("Alert: Unusual activity detected", "We've detected unusual activity on your account. Please confirm your identity.", "spam"),
        ("Bank Update: Account Information Needed", "Please provide your account information to avoid suspension.", "spam"),
        ("Verify Your Bank Account", "Click here to verify your bank account information immediately.", "spam"),
        ("Security Notice: Account Compromise", "Your account may have been compromised. Take action now to secure it.", "spam"),
        ("Monthly Bank Statement", "Your bank statement for August is now available. Click here to view.", "not_spam"),
        ("Account Update", "Your account information has been updated successfully.", "not_spam"),
        ("Bank Alert: Scheduled Maintenance", "Our banking systems will undergo maintenance on Saturday. No action is required.", "not_spam"),
        ("Friendly Reminder: Account Overdraft Protection", "You are eligible for overdraft protection. Learn more.", "not_spam"),
        ("Bank Promotion: Earn Rewards", "Earn rewards by using your account for more purchases this month.", "not_spam"),
        ("Congratulations, you've won!", "Click here to claim your $1000 prize.", "spam"),
        ("Reminder: Your account statement", "Please review your account statement.", "not_spam"),
        ("Urgent: Account verification", "Please verify your account information.", "spam"),
        ("Meeting agenda", "Here is the agenda for tomorrow's meeting.", "not_spam"),
        ("Get cheap meds now!", "Discounted prices on all meds, order now!", "spam"),
        ("Monthly newsletter", "Here are the updates from our company this month.", "not_spam"),
        ("Your friend sent you a message!", "Click to read the message from your friend.", "spam"),
        ("Flight booking confirmation", "Your flight has been successfully booked.", "not_spam"),
        ("Earn cash working from home", "Get paid $500/day by working from home.", "spam"),
        ("Security alert", "We've detected a login from an unknown device.", "not_spam"),
        ("Limited time offer!", "Shop now and get 50% off on all products!", "spam"),
        ("Job application update", "We have received your application for the position.", "not_spam"),
        ("You are a winner!", "Claim your $5000 gift card now!", "spam"),
        ("Reset your password", "Click here to reset your password.", "not_spam"),
        ("Amazing investment opportunity", "Double your money in just one month!", "spam"),
        ("Project update", "Here is the latest update on the project.", "not_spam"),
        ("Instant loan approval", "Get up to $10,000 approved instantly!", "spam"),
        ("Team meeting reminder", "Don't forget about the team meeting tomorrow.", "not_spam"),
        ("You've been selected!", "Claim your free vacation to the Bahamas.", "spam"),
        ("Invoice due", "Your invoice is due on the 15th of this month.", "not_spam"),
        ("Lose weight fast!", "Try our weight loss pills and see results in days.", "spam"),
        ("Birthday wishes", "Happy birthday! Hope you have a fantastic day!", "not_spam"),
        ("Act now to win big!", "Play now and win big prizes instantly.", "spam"),
        ("Project proposal", "Please review the attached project proposal.", "not_spam"),
        ("Your subscription is expiring", "Renew now to continue enjoying our services.", "spam"),
        ("Upcoming event reminder", "Don't miss our event this weekend.", "not_spam"),
        ("Claim your lottery winnings", "You have won $10,000, claim now!", "spam"),
        ("Service interruption notice", "Our services will be down for maintenance tonight.", "not_spam"),
        ("Get your free sample now", "Click here to receive your free sample of our new product.", "spam"),
        ("Your Amazon order has shipped", "Your order #12345 has been shipped and is on its way.", "not_spam"),
        ("Exclusive deal just for you!", "Save 70% on our latest collection, shop now!", "spam"),
        ("Meeting rescheduled", "The meeting has been moved to next Tuesday at 10 AM.", "not_spam"),
        ("You are pre-approved!", "You've been pre-approved for a $5000 loan, apply now!", "spam"),
        ("Family reunion details", "Here are the details for the family reunion this summer.", "not_spam"),
        ("Free gift card inside", "Click here to claim your $100 gift card.", "spam"),
        ("Weekly report", "Attached is the weekly report for your review.", "not_spam"),
        ("Hot singles in your area", "Meet local singles now, sign up for free!", "spam"),
        ("Quarterly financial report", "Please find the quarterly financial report attached.", "not_spam"),
        ("Your delivery is on the way", "Your package will arrive by tomorrow evening.", "not_spam"),
        ("Act fast! Limited time offer!", "Get 90% off all items, this offer expires soon!", "spam"),
        ("Client feedback requested", "We would appreciate your feedback on our latest project.", "not_spam"),
        ("You've been gifted!", "Someone sent you a gift card, click to redeem.", "spam"),
        ("System update complete", "The latest system update has been successfully installed.", "not_spam"),
        ("Find love today!", "Meet your soulmate with our dating app, sign up now!", "spam"),
        ("Your payment is past due", "Please pay your overdue invoice to avoid service interruption.", "not_spam"),
        ("You won't believe this!", "Make money online with this one weird trick!", "spam"),
        ("New job posting available", "Check out the latest job openings in your field.", "not_spam"),
        ("Unlock your free access", "Get free access to premium content, click here.", "spam"),
        ("Your package has been delivered", "Your recent order has been delivered to your address.", "not_spam"),
        ("Free iPhone just for you!", "Get a free iPhone, limited availability!", "spam"),
        ("Congratulations on your promotion", "Well deserved! Congrats on your new role.", "not_spam"),
        ("Start earning today!", "Sign up and start earning money immediately.", "spam"),
        ("Family dinner this weekend", "We are planning a family dinner this Saturday, are you in?", "not_spam"),
        ("You have unclaimed rewards", "Claim your rewards before they expire.", "spam"),
        ("Doctor's appointment confirmation", "Your appointment is confirmed for next Wednesday.", "not_spam"),
        ("Hurry! Flash sale ends tonight", "Shop now before the flash sale ends tonight.", "spam"),
        ("Holiday party details", "Here are the details for the holiday party next week.", "not_spam"),
        ("Urgent action required", "Your account has been compromised, reset your password now.", "spam"),
        ("Interview invitation", "We would like to invite you for an interview next week.", "not_spam"),
        ("Hot investment tips", "Invest in cryptocurrency and watch your money grow!", "spam"),
        ("Office closure notice", "The office will be closed on Friday due to maintenance.", "not_spam"),
        ("You've been chosen!", "You're the lucky winner of a new laptop, claim now!", "spam"),
        ("Training session reminder", "Reminder: The training session starts at 9 AM tomorrow.", "not_spam"),
        ("Get rich quick!", "Learn the secret to becoming rich fast with this program.", "spam"),
        ("Team outing invitation", "Join us for a team outing next Friday evening.", "not_spam"),
        ("Exclusive offer for you", "Get 75% off our entire collection, limited time only.", "spam"),
        ("Welcome to the team!", "We're excited to have you join our team, welcome aboard!", "not_spam"),
        ("Final notice: Payment due", "This is your final notice to pay your outstanding bill.", "spam"),
        ("Project deadline extended", "The project deadline has been extended by one week.", "not_spam"),
        ("Free membership trial", "Get a free trial of our premium membership, sign up now.", "spam"),
        ("New project assignment", "You have been assigned a new project, please review the details.", "not_spam"),
        ("Lose belly fat fast", "Try this new formula and lose belly fat in just one week.", "spam"),
        ("Wedding invitation", "You are invited to celebrate our wedding on September 20th.", "not_spam"),
        ("Exclusive discount for loyal customers", "Get 60% off your next purchase as a thank you for being loyal.", "spam"),
        ("Job offer", "We are pleased to offer you the position of Senior Developer.", "not_spam"),
        ("Immediate action required", "Your account will be deactivated unless you act now.", "spam"),
        ("Conference call details", "Here are the dial-in details for tomorrow's conference call.", "not_spam"),
        ("Your free gift is waiting", "Claim your free gift now, just pay shipping.", "spam"),
        ("Company newsletter", "Here is the latest edition of our company newsletter.", "not_spam"),
        ("Urgent: Update your payment info", "Your payment information needs to be updated immediately.", "spam"),
        ("Meeting follow-up", "Thank you for attending the meeting. Here is a summary of the discussion.", "not_spam"),
        ("Congratulations on your achievement", "We are proud to celebrate your success!", "not_spam"),
        ("Click to win a free car!", "Enter now for your chance to win a brand new car.", "spam"),
        ("Don't miss this opportunity", "Invest now and double your money in 30 days.", "spam"),
        ("Payment successful", "Your payment of $150 has been successfully processed.", "not_spam"),
        ("Important tax information", "Please review the attached document regarding your taxes.", "not_spam"),
        ("Win big with our latest promotion", "Play now and win big cash prizes instantly.", "spam"),
        ("New policy update", "Please review the updated company policy.", "not_spam"),
        ("You're the winner!", "You've won a luxury cruise vacation, click to claim.", "spam"),
        ("Appointment reminder", "This is a reminder for your appointment on Monday at 10 AM.", "not_spam")
    ]

        # Preprocess emails
        subjects_bodies = [" ".join([subject, body]) for subject, body, _ in emails]
        preprocessed_texts = [preprocess_text(text) for text in subjects_bodies]
        labels = [label for _, _, label in emails]

        # Vectorization
        vectorizer = TfidfVectorizer(max_df=0.85, max_features=1000)
        X = vectorizer.fit_transform(preprocessed_texts)
        y = labels

        # Split into training and test sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Model training
        model = RandomForestClassifier(random_state=42)
        param_grid = {
            'n_estimators': [50, 100],
            'max_depth': [10, 15],
            'min_samples_split': [2, 5],
        }
        grid_search = GridSearchCV(estimator=model, param_grid=param_grid, cv=3, n_jobs=-1, verbose=1)
        grid_search.fit(X_train, y_train)

        # Save the best model and vectorizer
        best_model = grid_search.best_estimator_
        joblib.dump(best_model, 'best_model_rf.pkl')
        joblib.dump(vectorizer, 'tfidf_vectorizer.pkl')
        print("Model trained and saved successfully.")
    else:
        print("The model has already been trained. Loading the saved model...")

# Function to analyze new emails
def analyze_email_ml(subject, body):
    # Load the model and vectorizer
    best_model = joblib.load('best_model_rf.pkl')
    vectorizer = joblib.load('tfidf_vectorizer.pkl')

    # Preprocess and vectorize the email
    email_content = preprocess_text(" ".join([subject, body]))
    email_vectorized = vectorizer.transform([email_content])
    
    # Predict if it's spam or not
    prediction = best_model.predict(email_vectorized)[0]
    return prediction