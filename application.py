import os
import socket
import re
import logging

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from flask_mail import Mail, Message


from helpers import apology, login_required, lookup, usd, password_checker

from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

# Configure application
app = Flask(__name__)

# Configure secret key
app.config['SECRET_KEY'] = 'e2f66b8e909e46e4a3824c6566f29caf'

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

@app.route("/")
@login_required
def index():

    # Obtain all relevant data for users portfolio
    shares_row = db.execute("SELECT * FROM shares WHERE user_id = :current_id", current_id = session["user_id"])
    user_cash = db.execute("SELECT cash FROM users WHERE id = :current_id", current_id = session["user_id"])
    quote_list = []
    users_share_holdings = 0

    # Get current value of users stocks, append to list (no append or add method for dict) and calculate users total share value
    for share in shares_row:
        quote_dict = lookup(share["symbol"])
        quote_list.append(quote_dict)
        users_share_holdings += float((share["number_of_shares"]) * quote_dict["price"])

    # Calculate users total holdings (shares + cash) in USD
    users_total_holdings = usd(users_share_holdings + float(user_cash[0]["cash"]))

    return render_template("index.html", shares_row = shares_row, quote_list = quote_list, usd = usd, user_cash = user_cash, users_total_holdings = users_total_holdings)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = (request.form.get("symbol")).upper()
        shares = request.form.get("shares")
        buy_dict = lookup(symbol)

        # Ensure user has entered a valid stock symbol
        if not symbol or buy_dict == None:
            flash("You must enter a valid stock symbol", "error")
            return redirect(url_for("buy"))

        # Ensure user has entered a valid share value
        elif shares.isnumeric() != True or float(shares).is_integer() != True or float(shares) <= 0:
            flash("You must request a share value that is a positive integer", "error")
            return redirect(url_for("buy"))

        else:
            buy_list = list(dict.values(buy_dict))

            # Query users current cash
            rows = db.execute("SELECT * FROM users WHERE id = :current_id", current_id = session["user_id"])
            user_cash = rows[0]["cash"]

            # Check if user has enough cash for transaction
            total_share_price = (float(shares) * (buy_list[1]))
            if total_share_price > user_cash:
                flash("You cannot afford that many shares", "error")
                return redirect(url_for("buy"))

            else:
                # Update transaction table with users transaction
                db.execute("INSERT INTO transactions (user_id, action, symbol, share_price, number_of_shares, total_cost, date) VALUES (:user_id, :action, :symbol, :share_price, :number_of_shares, :total_cost, :date)", user_id = session["user_id"], action="Buy", symbol=symbol, share_price=buy_list[1], number_of_shares=shares, total_cost=total_share_price, date=datetime.now())

                # Update users cash value
                new_cash = user_cash - total_share_price
                db.execute("UPDATE users SET cash = :new_cash WHERE id = :current_id", new_cash = new_cash, current_id = session["user_id"])

                # Update shares table with users new shares
                # Check if share symbol in shares table for users ID
                count = db.execute("SELECT * FROM shares WHERE user_id = :current_id AND symbol = :symbol", current_id = session["user_id"], symbol=symbol)
                if len(count) == 0:
                    db.execute("INSERT INTO shares (user_id, symbol, number_of_shares) VALUES (:user_id, :symbol, :number_of_shares)", user_id = session["user_id"], symbol = symbol, number_of_shares = shares)
                else:
                    db.execute("UPDATE shares SET number_of_shares = number_of_shares + :shares WHERE user_id = :current_id AND symbol = :symbol", shares = shares, current_id = session["user_id"], symbol = symbol)

                # Flash message to tell user transaction was successful
                flash("Bought!", category = "success")

                return redirect("/")

@app.route("/history")
@login_required
def history():
    transaction_rows = db.execute("SELECT * FROM transactions where user_id = :current_user", current_user = session["user_id"])
    return render_template("history.html", transaction_rows = transaction_rows, usd = usd)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    if request.method == "GET":
        return render_template("login.html")

    else:
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("You must provide username", "error")
            return render_template("login.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("You must provide password", "error")
            return render_template("login.html")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Invalid username and/or password", "error")
            return render_template("login.html")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = (request.form.get("symbol")).upper()

        # Store dict return value for stock quote (name, price, symbol)
        quoted_dict = lookup(symbol)

        if not symbol or quoted_dict == None:
            flash("You must enter a valid stock symbol", "error")
            return redirect(url_for("quote"))

        # Store dict values into list
        quoted_list = list(dict.values(quoted_dict))
        return render_template("quoted.html", quoted_list=quoted_list, usd = usd)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        email_row = db.execute("SELECT * FROM users WHERE email = :email", email = email)
        username_row = db.execute("SELECT * FROM users WHERE username = :username", username = username)

        #Ensure user typed a valid username
        if not username or not email:
            flash("You must enter a valid email address and username", "error")
            return redirect(url_for("register"))

        # Ensure user typed a valid password
        elif not password or not confirmation:
            flash("You must provide and confirm a password", "error")
            return redirect(url_for("register"))

        # Ensure users passwords match
        elif password != confirmation:
            flash("Your passwords do not match", "error")
            return redirect(url_for("register"))

        # Check if password satisfies requirements
        elif password_checker(password) == False:
            flash("Your password must satisfy the requirements", "error")
            return redirect(url_for("register"))

        elif len(email_row) != 0:
            flash("Account registered with email address, have you already registered?", "error")
            return redirect(url_for("register"))

        # Ensure username not already taken
        elif len(username_row) != 0:
            flash("Username already taken", "error")
            return redirect(url_for("register"))

        # Store users email, username and password hash into database
        else:
            db.execute("INSERT INTO users (username, hash, email) VALUES (:username, :hashed, :email)", username = username, hashed = generate_password_hash(password, method = 'pbkdf2:sha256', salt_length=8), email = email)
            return redirect("/")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "GET":

        # Get users current shares to populate select menu in sell.html
        shares_row = db.execute("SELECT * FROM shares WHERE user_id = :current_user", current_user = session["user_id"])
        return render_template("sell.html", shares_row=shares_row)

    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Ensure user has chosen a stock symbol
        if not symbol:
            flash("You must enter a valid stock symbol", "error")
            return redirect(url_for("sell"))

        # Ensure user has entered a valid share value
        if shares.isnumeric() != True or float(shares).is_integer() != True or float(shares) <= 0:
            flash("You must request a share value that is a positive integer", "error")
            return redirect(url_for("sell"))

        else:
            # Obtain all relevant data to update database with users sale
            sell_dict = lookup(symbol)
            sell_list = list(dict.values(sell_dict))
            total_share_price = (float(shares) * (sell_list[1]))
            shares_number = db.execute("SELECT number_of_shares FROM shares WHERE user_id = :current_user AND symbol = :symbol", current_user = session["user_id"], symbol = symbol)

            # Ensure user has enough shares to sell
            if int(shares_number[0]['number_of_shares']) < int(shares):
                flash("You don't have that many shares", "error")
                return redirect(url_for("sell"))

            # If number of shares sold equals the total amount of shares they have, remove row from shares table, update users cash and add transaction to transaction table
            elif int(shares_number[0]['number_of_shares']) == int(shares):

                # Remove row from shares table
                db.execute("DELETE FROM shares WHERE user_id = :current_user AND symbol = :symbol", current_user = session["user_id"], symbol = symbol)

                # Update users cash value
                db.execute("UPDATE users SET cash = cash + (:shares * :share_price) WHERE id = :current_user", shares = float(shares), share_price = sell_list[1], current_user = session["user_id"])

                # Update transaction table with users transaction
                db.execute("INSERT INTO transactions (user_id, action, symbol, share_price, number_of_shares, total_cost, date) VALUES (:user_id, :action, :symbol, :share_price, - :number_of_shares, :total_cost, :date)", user_id = session["user_id"], action="Sell", symbol=symbol, share_price=sell_list[1], number_of_shares=shares, total_cost=total_share_price, date=datetime.now())

            # Else simply update users amount of shares and cash, and add transaction to transaction table
            else:

                # Update users table with users total amount of shares
                db.execute("UPDATE shares SET number_of_shares = number_of_shares - :shares WHERE user_id = :current_id AND symbol = :symbol", shares = shares, current_id = session["user_id"], symbol = symbol)

                # Update transaction table with users transaction
                db.execute("INSERT INTO transactions (user_id, action, symbol, share_price, number_of_shares, total_cost, date) VALUES (:user_id, :action, :symbol, :share_price, - :number_of_shares, :total_cost, :date)", user_id = session["user_id"], action="Sell", symbol=symbol, share_price=sell_list[1], number_of_shares=shares, total_cost=total_share_price, date=datetime.now())

                # Update users cash value
                db.execute("UPDATE users SET cash = cash + (:shares * :share_price) WHERE id = :current_user", shares = float(shares), share_price = sell_list[1], current_user = session["user_id"])

            # Flash message to tell user transaction was successful
            flash("Sold", "success")

            return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
