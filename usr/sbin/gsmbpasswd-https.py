#!/usr/bin/python
# -*- coding:utf-8 -*-
# In order to use swedish characters we tell python to interpret
# the characters in this file as utf-8.

import logging
from logging.handlers import TimedRotatingFileHandler
# Needed in order to get settings from the configuration file
from ConfigParser import SafeConfigParser
# So we can save the current time when logging an event
from datetime import datetime
# To generate secure values for things like for secret_key 
from os import urandom
# So we can encode the output from urandom into a string 
# with characters that are safe to use.
from base64 import urlsafe_b64encode
# Main module for a alot of regular expression operations
import re
# This exception is raised upon connection errors
from socket import error as socket_error

# These options are defined in pyOpenSSL, so that
# we do not have to lookup their value in the
# source-code of OpenSSL when we want to use them.
from OpenSSL.SSL import OP_NO_SSLv2, OP_NO_SSLv3

# The main web.py framework, see http://webpy.org 
import web
# CherryPy WSGI Server with support for SSL
from web.wsgiserver import CherryPyWSGIServer

# So that we can specify the maximum amount of data sent by
# clients that we consider legitimate.
import cgi

# This is the recommended, backported, module for starting programs 
# and communicating with them (smbpasswd in this program).
from subprocess32 import Popen, PIPE, STDOUT, TimeoutExpired
# The pysmb project includes a pure Python implementation of
# the NTLMv2 protocol that we can use for authentication.
# Installing pysmb via pip is required.
from smb.SMBConnection import SMBConnection

# To show detailed information when the program crashes. 
# When the program is put into actual use, disable this 
# function with "False". 
web.config.debug = False

CONF_FILE = u'etc/gsmbpasswd/gsmbpasswd.conf'
config = SafeConfigParser()
config.read(CONF_FILE)

TRANSLATED_MESSAGES_FILE = u'etc/gsmbpasswd/gsmbpasswd-messages.conf'
message_conf = SafeConfigParser()
message_conf.read(TRANSLATED_MESSAGES_FILE)
# Get the whole dictionary with sections and options
message_dictionary = message_conf._sections

HTML_TEXT_FILE = u'etc/gsmbpasswd/gsmbpasswd-html.conf'
html_conf = SafeConfigParser()
html_conf.read(HTML_TEXT_FILE)
# Get the whole dictionary with sections and options
html_dictionary = html_conf._sections
# Get only the sections that show which languages we support
html_languages = html_conf.sections()

# Use either ip address or domain name to specify your samba server 
SMB_SERVER = config.get(u'SMBServer', u'ServerName')

# Path to directory for html files
TEMPLATES = config.get(u'HTML', u'Directory')

# Enable to use SSL certificates. 
# This code is taken from http://webpy.org/cookbook/ssl
CherryPyWSGIServer.ssl_certificate = config.get(u'SSLCertificate', u'Certificate')
CherryPyWSGIServer.ssl_private_key = config.get(u'SSLCertificate', u'PrivateKey')

# The maximum and minimum number of letters that is allowed for username and password
# These values are specified in the config file
MAX_USERNAME = config.getint(u'User', u'MaxUserChar')        
MIN_USERNAME = config.getint(u'User', u'MinUserChar')
MAX_PASSWORD = config.getint(u'Password', u'MaxPassChar') 
MIN_PASSWORD = config.getint(u'Password', u'MinPassChar')

# The settings for the RotateLog class
LOGFILE = config.get(u'Log', u'LogFile')
LOGFORMAT = config.get(u'Log', u'LogFormat', raw = True)
TIMEFORMAT = config.get(u'Log', u'TimeFormat', raw = True)
ROTATE_TIME = config.get(u'Log', u'RotateTime')
BACKUP_DAYS = config.get(u'Log', u'BackupDays')
 
URLS = (
    u'/', u'Index'
)

# Create an application with the URLs listed and look up the
# classes in the global namespace of this file.
app = web.application(URLS, globals())

web.config.session_parameters[u'cookie_name'] = u"gsmbpasswd"

# Number of second of inactivity that is allowed before the session expires
web.config.session_parameters[u'timeout'] = 1200

# Explicitly set this to false so that the
# program do not ignore the timeout set above.
web.config.session_parameters[u'ignore_expiry'] = False

# Message displayed when the session expires
web.config.session_parameters[u'expired_message'] = u"Session expired. Please reload the page and try again."

# The session is only valid when accessed from the same 
# ip address that created the session.
web.config.session_parameters[u'ignore_change_ip'] = False

# Explicitly set the secure flag for cookies since this is not 
# done by the default. See https://www.owasp.org/index.php/SecureFlag
web.config.session_parameters[u'secure'] = True

# Use urandom to generate a new secret value to use as a SALT when 
# creating new session cookies instead of using the hardcoded default value.
web.config.session_parameters[u'secret_key'] = urlsafe_b64encode(urandom(30))

# Explicitly set httponly to True since we can
# not allways trust the default to so for us.
# For more info: https://www.owasp.org/index.php/HTTPOnly
web.config.session_parameters[u'HttpOnly'] = True

# Disable the use of the deprecated protocol SSLv2 and the insecure protocol
# SSLv3 used in the POODLE-attack(CVE-2014-3566). Also disable TLS compression
# that is used in the CRIME-attack (CVE-2012-4929) but for which there is no
# variable assigned in the old pyOpenSSL module shipped with Debian 7.
# We therefore use the integer value 131072 (0x00020000 in hex) as seen in the
# source code of OpenSSL.
web.config.ssl_parameters[u'ssl_options'] = OP_NO_SSLv2 | OP_NO_SSLv3 | 131072

# Use ciphers from the HIGH-group with the exception of RC4-SHA which we must
# support in order to be compatible with Windows XP. The included pyOpenSSL
# is a bit old in Debian 7 and the HIGH-group will therefore not include any
# ciphers that supports forward secrecy. However this still gives us a A-
# rank on the test below which is better than what most banks provides
# and is PCI-compliant.
# For more info, see: https://www.ssllabs.com/ssltest/index.html
web.config.ssl_parameters[u'ssl_cipher_list'] = 'HIGH:RC4-SHA:!aNULL:!eNULL:!EXP:!LOW:!3DES:!MD5:!PSK:!DSS:!SEED@STRENGTH'

# The maximum amount of data sent to the application that we consider legitimate.
# This corresponds to 1024 byte or approximately 2 times more than a POST in
# which all values include 127 characters.
cgi.maxlen = 1024

# This trick is needed if we want to run in debug mode, that is if we have
# set web.config.debug = True, and use sessions. Implemented as seen on:
# http://webpy.org/cookbook/session_with_reloader
#if web.config.get(u'_session') is None:
session = web.session.Session(app, web.session.DiskStore(u'sessions'))
#    web.config._session = session
#else:
#    session = web.config._session

class RotatingLog(object):

    # Get a logger with the provided name when initializing
    # this class and use a handler that rotates the logfiles
    # based on time as seen below.
    def __init__(self, logger_name):
        self._logger = logging.getLogger(logger_name)

        # We only want one handler, so only add a handler
        # if there isn't already one configured. 
        if len(self._logger.handlers) == 0:
            # The messages shouldn't be sent to other logs 
            self._logger.propagate = False

            # We only use one logger and don't differentiate
            # between the importance of different messages
            # and therefore use DEBUG as the only logg-level.
            self._logger.setLevel(logging.DEBUG)

            # Rotate the log, if not empty, at midnight
            # and save up to 90 days of log-files.
            self._handler = TimedRotatingFileHandler(
                LOGFILE, when = ROTATE_TIME, backupCount = BACKUP_DAYS, encoding = u'UTF-8')
            
            self._handler.setLevel(logging.DEBUG)
            self._handler.setFormatter(logging.Formatter(LOGFORMAT, TIMEFORMAT))
            self._logger.addHandler(self._handler)

    # Write the message, if not empty, to the log-file
    def write(self, message):
        if not message.lstrip().rstrip() == u'':
            self._logger.debug(message)

rotating_log = RotatingLog(u'gsmbpasswd_log')

# Send messages to the log with time and client ip addresses. 
# strftime() creates a string of the datetime object in the format specified.
def log_to_file(log_msg):
    rotating_log.write(u"[" + web.ctx.ip + u"] " + log_msg)

# Send messages from smbpasswd to the log. 
def smbpasswd_output_to_logfile(smbpasswd_output):
    rotating_log.write(u"[" + web.ctx.ip + u"] " + u"<smbpasswd> " + smbpasswd_output)

# Get the appropriate and translated message from the file
# specified in the variable TRANSLATED_MESSAGES_FILE
def translate_message(function_id, message_id):
    if session.has_key(u"client_language"):
        language = session.get(u'client_language')
        dict_option = message_id + u"_" + language

        if message_dictionary.has_key(function_id):
            if dict_option in message_dictionary[function_id]:
                return message_dictionary[function_id][dict_option]

            else:
                log_to_file(u"ConfigError: Missing translated message,"
                            u" language: " + language +
                            u" function_id: " + function_id +
                            u" message_id: " + message_id)
                return (u"Error: No message is available. "
                        u"Please contact your system administrator.")
        else:
            log_to_file(u"ConfigError: Missing function section,"
                        u" language: " + language +
                        u" function_id: " + function_id +
                        u" message_id: " + message_id)
            return (u"Error: No message is available. "
                    u"Please contact your system administrator.")
    else:
        log_to_file(u"Error: The client removed its cookie "
                    u"during an active session")
        return u"Please try again."

# Get the appropriate text in the appropriate language from the file
# specified in the variable HTML_TEXT_FILE
def get_html_text():
    if session.has_key(u'client_language'):
        if session.client_language in html_languages:
            return dict(html_dictionary[session.client_language])
        else:
            log_to_file(u"ConfigError: Missing language-section for "
                        u"language: " + session.client_language + " in gsmbpasswd-html.conf")
            raise web.InternalError(message = u"ConfigError: No such available language. "
                                              u"Please contact your system administrator.")
    else:
        log_to_file(u"Error: The client removed its cookie during an active session")
        raise web.HTTPError(u"400 Bad request", {u'content-type':u'text/html'},
                            u"Error: This site requires cookies. Please reload the page "
                            u"and try again.")

# Protect forms from CSRF attacks. See http://webpy.org/cookbook/csrf
# Create a unique value for 'csrf_token' on the html page for each user.
def csrf_token():
    if not session.has_key(u'csrf_token'):
        from uuid import uuid4
        session.csrf_token = uuid4().hex
    return session.csrf_token

def csrf_protected(f):
    def decorated(*args, **kwargs):
        # By getting the input from the user in a try-except statement we can 
        # catch UnicodeDecodeError and hence make sure that the input was 
        # provided in the right encoding.
        try:
            input_from_user = web.input()

            # If the user did not send us the csrf_token it did not
            # use the right page when submitting the information.
            if not input_from_user.has_key(u'csrf_token'):
                log_to_file(u"WARNING: Cross-site request forgery (CSRF) attempt "
                            u"or brute-force attack without the csrf_token.")
                return render.index(result = u'Please try again', args = get_html_text())
            
            # The value of the csrf_token that we expect from the user must be
            # the same as the one that we included in the html-code for this 
            # request and saved a copy of in the user's session.
            elif not input_from_user.csrf_token == session.pop(u'csrf_token', None):
                log_to_file(u"WARNING: Cross-site request forgery (CSRF) attempt "
                            u"or retransmission of old or incorrect csrf-token.") 
                return render.index(result = u'Please try again', args = get_html_text())
            
            # Check if there are five keys as specified in the html-code.  
            # keys() returns a copy of the dictionary's list of keys.
            if not len(input_from_user.keys()) == 5:
                log_to_file(u"WARNING: A malicious user sent a different amount of keys "
                            u"than required on the html-page")
                raise web.HTTPError(u"400 Bad request", {u'content-type':u'text/html'},
                                    u"400 Bad request. This violation will be reported.")

            # Check if the five keys are username, 3 passwords and csrf_token.
            # This is an else statement since it can only be a valid control
            # if it has been verified that 5 keys where provided by the user.
            else:
                if (not input_from_user.has_key(u'username') or
                    not input_from_user.has_key(u'current_password') or 
                    not input_from_user.has_key(u'new_password') or 
                    not input_from_user.has_key(u'new_password_second')):
                    log_to_file(u"WARNING: A malicious user did not send all of the "
                                u"required user-controlled variables on the html page.")
                    raise web.HTTPError(u"400 Bad request", {u'content-type':u'text/html'},
                                        u"400 Bad request. This violation will be reported.")

        except UnicodeDecodeError:
            log_to_file(u"WARNING: A malicious user tried to crash the "
                        u"application by sending non-unicode input")
            return render.index(result = u'Please try again', args = get_html_text())

        except ValueError:
            log_to_file(u"WARNING: A malicious user tried to perform a DOS-attack "
                        u"by sending a lot more data than we should normally receive.")
            raise web.HTTPError(u"400 Bad request", {u'content-type':u'text/html'},
                                u"400 Bad request. This violation will be reported.")
 
        # As recommended for Python this program shall deal only with UTF-8 internally.
        # The try-except statement above should take care of this, but to make
        # sure we check if the input is unicode in case that the internal functioning
        # of web.py changes in the future and starts supporting other encodings. 
        try:
            if (not isinstance(input_from_user.username, unicode) or
                not isinstance(input_from_user.current_password, unicode) or
                not isinstance(input_from_user.new_password, unicode) or
                not isinstance(input_from_user.new_password_second, unicode) or
                not isinstance(input_from_user.csrf_token, unicode)):
                log_to_file(u"Error: Non UTF-8 encoding was used.")
                msg_to_web = (u"Error: Something is wrong with your browser "
                              u"since it did not use the specified UTF-8 encoding.")
                return render.index(result = msg_to_web, args = get_html_text())
        
        # This should never occur since we check that the right keys are provided
        # to us by the user with 'input_from_user.has_key()' above.
        except NameError:
            log_to_file(u"Error: A malicious user managed to leave one of the variables unassigned.")
            raise web.HTTPError(u"400 Bad request", {u'content-type':u'text/html'},
                                u"400 Bad request. This violation will be reported.")
             
        return f(*args, **kwargs)
    return decorated

# Check if all the input from the user is considered valid before proceeding. 
def basic_input_test(username, current_password, new_password, new_password_second):
    valid_input = False
    msg_to_web = None
     
    if not re.search(u'[\w-]', username):
        log_to_file(u"Error: Illegal characters for USERNAME.") 
        msg_to_web = translate_message(u"basic_input_test", u"1")
        valid_input = False
        
    elif len(username) > MAX_USERNAME:
        log_to_file(u"Error: Too long string for USERNAME")
        msg_to_web = translate_message(u"basic_input_test", u"2")
        valid_input = False
        
    elif len(username) < MIN_USERNAME:
        log_to_file(u"Error: Too short string for USERNAME")
        msg_to_web = translate_message(u"basic_input_test", u"3")
        valid_input = False
        
    elif len(current_password) > MAX_PASSWORD:
        log_to_file(u"Error: User: %s: Too long string for OLD PASSWORD." % username)
        msg_to_web = translate_message(u"basic_input_test", u"4")
        valid_input = False
        
    elif len(new_password) > MAX_PASSWORD:
        log_to_file(u"Error: User: %s: Too long string for NEW PASSWORD." % username)
        msg_to_web = translate_message(u"basic_input_test", u"5")
        valid_input = False
        
    elif not new_password == new_password_second:
        msg_to_web = translate_message(u"basic_input_test", u"6")
        valid_input = False
    
    else:
        log_to_file(u"INPUT_OK: User: %s input verified as non-malicious" % username)
        valid_input = True
    
    return valid_input, msg_to_web

# Authenticate a username and its password 
def authenticate_user(username, password):
    authenticated_user = False
    auth_username = None
    msg_to_web = None

    # This function takes advantage of the following characteristics of the NTLMv2 protocol. 
    # A message of successful authentication is returned from the server in two cases: 
    # 1. A existent user authenticated with the server using a valid password. 
    # 2. A non-existent user tried to authenticate with the server. 
    # If a existing user tries to authenticate with the wrong password the NTLMv2 protocol 
    # will notify the user that it could not authenticate. Therefore by using a randomly 
    # created, wrong password, we can check if the username exists on the server. 
    # (Whether smbclient allows a guest user or not depends on the parameter "map to guest" 
    # in /etc/samba/smb.conf)
    def is_username_correct(username):
        username_exist = False    
        incorrect_password = urlsafe_b64encode(urandom(30))

        conn = SMBConnection(
            username, incorrect_password, 'gsmbpasswd-server', SMB_SERVER, use_ntlm_v2 = True)

        try:
            if not conn.connect(SMB_SERVER, 445):
                username_exist = True
            else:
                username_exist = False

        except:
            # Re-raise the same exception that was thrown and let
            # the calling function handle the exception.
            raise
             
        finally:
            if not conn == None:
                conn.close # Always close the connection

        return username_exist

    # Authenticate a user by first checking that the username is correct and exist 
    # on the server and then proceeds to authenticate the user with the supplied password.
    def verify_user(username, password):
        verified_username_and_password = False
        msg_to_web = None 

        conn = None
        
        try:
            if is_username_correct(username):
                conn = SMBConnection(
                    username, password, 'gsmbpasswd-server', SMB_SERVER, use_ntlm_v2 = True)
                verified_username_and_password = conn.connect(SMB_SERVER, 445)
            else:
                verified_username_and_password = False
                log_to_file(u"WARNING: Someone entered a non-existent username: %s" % username)
 
        except:
            # Re-raise the same exception that was thrown and let
            # the calling function handle the exception.
            raise
       
        finally:
            if not conn == None:
                conn.close # Always close the connection

        return verified_username_and_password, msg_to_web

    try: 
        verified_username_and_password, msg_to_web = verify_user(username, password)

        if  verified_username_and_password:
            log_to_file(u"AUTH_SUCCESS: User: %s authenticated successfully!" % username)
            auth_username = username
            authenticated_user = True
        else:
            msg_to_web = translate_message(u"authenticate_user", u"1") 
            log_to_file(u"AUTH_FAIL: User: %s could not authenticate." % username)
            authenticated_user = False

    # If the user cannot connect to the samba server, for example because giving a wrong name  
    # in the config fil, the error messages are shown on the web site and the log.  
    except socket_error:
        log_to_file(u"Config Error: Could not connect to the server!")
        msg_to_web = translate_message(u"authenticate_user", u"2")

    return authenticated_user, auth_username, msg_to_web

# Password will be checked according to the length and characters
# See even: https://www.owasp.org/index.php/Codereview-Authentication
# If the new password is not valid, change back the temporary password 
# to the current password.
def password_input_test(username, current_password, new_password):
    valid_input_password = False
    msg_to_web = None
    
    # Allow password to contain alphanumerical and special characters. 
    # See http://www.fileformat.info/info/charset/UTF-8/list.htm
    if not re.search(u'[!"#$%&\'()*+,-./:;<=>?@[\\]^_{|}~\w]', new_password): 
        log_to_file(u"Error: Illegal characters for NEW PASSWORD.")
        msg_to_web = translate_message(u"password_input_test", u"1")
        valid_input_password = False

    elif len(new_password) < MIN_PASSWORD:
        log_to_file(u"Error: Too short string for NEW PASSWORD.")
        msg_to_web = translate_message(u"password_input_test", u"2")
        valid_input_password = False

    elif new_password == current_password:
        log_to_file(u"Error: The new and current password was the same.")
        msg_to_web = translate_message(u"password_input_test", u"3")
        valid_input_password = False
    
    else:
        valid_input_password = True 

    return valid_input_password, msg_to_web 

def change_password(username, current_password, new_password):
    msg_to_web = None
    
    # Popen executes smbpasswd as a child program in a new process,
    # with arguments to the program smbpasswd in a list [].
    #
    # The -s option causes smbpasswd to read from stdin instead of prompting the user.
    # The -U [username] option allows a user to change his/her own password.
    #
    # stdin, stdout and stderr are assigned as PIPE so that we can
    # use communicate() to provide input to stdin of smbpasswd and
    # get message of both success and error back from the program.
    #
    # shell=False in order to avoid the security risk with shell 
    # injection from unsanitized input such as "input; rm -rf /".
    smbpasswd_proc = Popen([u"smbpasswd", u"-s", u"-r", SMB_SERVER, u"-U", username],
                                 stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=False)

    try:
        # Space, '.' and newline are inconsistently used in the output from smbpasswd
        # and therefore we strip those characters from the end of the output so that
        # we can do sane regex matching without fearing that one day someone will fix
        # this and break our application.
        smbpasswd_output = (smbpasswd_proc.communicate(
                                    input=(current_password + u'\n'
                                           + new_password   + u'\n'
                                           + new_password   + u'\n')
                                           .encode("UTF-8"), timeout=30)[0]
                                           ).rstrip(u' .\n') 
    except TimeoutExpired:
        smbpasswd_proc.kill()
        log_to_file(u"TIME_OUT: User: %s: subprocess.communicate timed out." % username)
        smbpasswd_output_to_logfile(smbpasswd_output)
        return u"The operation timed out. Please contact your system administrator."

    # According to the output from smbpasswd, decide what message should be shown 
    # in the log and on the web page. 
    if smbpasswd_output.endswith(u'NT_STATUS_LOGON_FAILURE'):
        msg_to_web = translate_message(u"change_password", u"1") 
        log_to_file("AUTH_FAIL: User: %s entered invalid USERNAME or PASSWORD." % username)
        smbpasswd_output_to_logfile(smbpasswd_output)

    # Not all configurations of samba provides this information.
    # "map to guest = bad user" is needed in /etc/samba/smb.conf to make this work.         
    elif smbpasswd_output.endswith(u'NT_STATUS_RPC_PROTOCOL_ERROR'):
        msg_to_web = translate_message(u"change_password", u"2")
        log_to_file(u"Error: User: %s: Incorrect USERNAME" % username)
        smbpasswd_output_to_logfile(smbpasswd_output)

    elif smbpasswd_output.endswith(u'NT_STATUS_UNSUCCESSFUL'):
        msg_to_web = translate_message(u"change_password", u"3")
        log_to_file(u"Error: Could not connect to the Samba server. " 
                    u"Server down or unreachable.")
        smbpasswd_output_to_logfile(smbpasswd_output)

    elif smbpasswd_output.endswith(u'NT_STATUS_INVALID_PARAMETER'):
        msg_to_web = translate_message(u"change_password", u"4")
        log_to_file(u"Error: Invalid parameter detected for smbpasswd.")
        smbpasswd_output_to_logfile(smbpasswd_output)

    elif smbpasswd_output.endswith(u'Error was : Password restriction'):
        msg_to_web = translate_message(u"change_password", u"5")
        log_to_file(u"Error: User: %s tried to change her/his password. But it did " 
                    u"not conform to the policy set by Samba" %  username)
        smbpasswd_output_to_logfile(smbpasswd_output)
    
    elif smbpasswd_output.startswith(u'Unable to find an IP address for'):
        msg_to_web = translate_message(u"change_password", u"6")
        log_to_file(u"ServerName_Error: Server name/address in gsmbpasswd.conf is invalid.")
        smbpasswd_output_to_logfile(smbpasswd_output)
     
    elif smbpasswd_output.startswith(u'Password changed for user'):
        msg_to_web = translate_message(u"change_password", u"7")
        log_to_file(u"SUCCESS: User: %s changed password successfully." % username)
        smbpasswd_output_to_logfile(smbpasswd_output)
        
    return msg_to_web

render = web.template.render(TEMPLATES, globals={u'csrf_token':csrf_token})

class Index:
    def GET(self):
        # Protect against downgrade attacks such as the SSL stripping
        # attack devised by Moxie Marlinspike by telling the client
        # that any subsequent connection during the next 20 years
        # must be made using HTTPS. Any errors in the HTTPS certificate
        # or handshake are fatal without any option for override
        # so that a MITM-attack using a self-signed certificate
        # will not be able to succeed. 31536000 = 20 years in seconds.
        web.header(u"Strict-Transport-Security", u"max-age=31536000")

        # For the clients that supports it, use a very restrictive CSP
        # policy allowing only the HTML-code, images and CSS to load and
        # only if they are from the the same origin.
        # Preferably we would like to define the FQDN the program is installed at
        # and that only HTTPS should be used for connecting to it.
        #web.header(u"Content-Security-Policy", u"default-src 'none'; img-src 'https://limepw.lime.ki.se'; style-src 'https://limepw.lime.ki.se'")
        web.header(u"Content-Security-Policy", u"default-src 'none'; img-src 'self'; style-src 'self'")

        # This helps us to mitigate clickjacking attacks, by telling
        # the client that that our content should not be not embedded
        # into other sites. See http://blog.whitehatsec.com/x-frame-options
        web.header(u"X-Frame-Options", u"DENY")

        # Tell the client to not rely on a old version of the page so that it
        # will ask for a new version each time that includes the correct csrf_token
        # See: http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.1 
        web.header(u"Cache-Control", u"no-cache, no-store, max-age=0, s-maxage=0, must-revalidate")

        # The value 0 make the client treat the page as already expired
        # See: http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.21
        web.header(u"Expires", u"0")

        # If the client ends up here it is because they manually selected
        # to change language by i.e. clicking on a link to the english-page.  
        if web.ctx.environ.has_key(u'QUERY_STRING'):
            # Store the value in a variable to make it easier to handle
            query_string = web.ctx.environ.get(u'QUERY_STRING')
            # Check if the query string acctually contains anything
            if not len(query_string) == 0:
                # This is the format the supported query string can take
                if re.match(u'^lang=[a-z]{2}$', query_string):
                    # Check if the language specified in the
                    # query string is a language that we support.
                    if query_string.lstrip(u'lang=') in html_languages:
                        # Store the determined language in a session variable 
                        # and return the page in the language requested.
                        session.client_language = query_string.lstrip(u'lang=')
                        return render.index(result = None, args = get_html_text())
                    else:
                        # This would only happen if the client manually changed the URL
                        log_to_file(u"WARNING: A client manually selected an URL specifying "
                                    u"a QUERY_STRING with a language we do not support.")
                        raise web.HTTPError(u"400 Bad request", {u'content-type':u'text/html'},
                                            u"Error: Invalid URL. Please reload the page and try again.")
                else:
                    log_to_file(u"WARNING: A malicious user is trying to find a "
                                u"vulnerability in the program by trying different "
                                u"query strings.")
                    raise web.HTTPError(u"400 Bad request", {u'content-type':u'text/html'},
                                        u"400 Bad request. This violation will be reported.")
 
        # Check if we have already determined the client's prefered language.
        if session.has_key(u"client_language"):
            if session.client_language in html_languages:
                return render.index(result = None, args = get_html_text())
            else:
                log_to_file(u"WARNING: Something is seriously wrong. "
                            u"session.client_language has a been assigned a "
                            u"language: " + session.client_language +
                            u"but it is not included in html_languages.")
                raise web.InternalError(message = u"Please contact your system administrator.")

        else: 
            # Check if the client sent a header with its prefered language
            if web.ctx.environ.has_key(u"HTTP_ACCEPT_LANGUAGE"):
                # Store the value in a variable to make it easier to handle
                http_accept_language = web.ctx.environ.get(u"HTTP_ACCEPT_LANGUAGE")
                # Check if the header acctually contains anything
                if not len(http_accept_language) == 0:
                    # Check if the first language in the header conforms to
                    # RFC2616 or if it is some kind of malformed request.
                    if re.match(u'^([a-zA-Z]{2}$)|([a-zA-Z]{2}[,;]{1})|([a-zA-Z]{2}-[a-zA-Z]{2}[,;]{1})', http_accept_language):
                        # Check if the header matches any of the supported languages.
                        # We convert the first two characters to lower case, because
                        # RFC2616 states that they are case-insensitive.
                        if web.ctx.environ.get(u"HTTP_ACCEPT_LANGUAGE")[:2].lower() in html_languages:
                            session.client_language = web.ctx.environ.get(u"HTTP_ACCEPT_LANGUAGE")[:2]
                        else:
                            # The default language is the first one configured
                            session.client_language = html_languages[0]
                        
                        # session.client_language is now set and we can therefore
                        # show the page in the correct language for the client.
                        return render.index(result = None, args = get_html_text())
                         
                    else:
                        log_to_file(u"WARNING: A client did not send a HTTP_ACCEPT_LANGUAGE "
                                    u"header with at least one language that conforms to RFC2616.")
                else:
                    log_to_file(u"WARNING: A client sent an empty a HTTP_ACCEPT_LANGUAGE header")
            else:
                log_to_file(u"WARNING: A client did not send the header HTTP_ACCEPT_LANGUAGE")

        # Implicit deny 
        raise web.HTTPError(u"400 Bad request", {u'content-type':u'text/html'},
                            u"Error: Your web browser is not acting normally, "
                            u"please check your settings and try again.")
 
    @csrf_protected
    # Use POST so that the input are not shown in the URL-bar. 
    def POST(self):
        web.header(u"Strict-Transport-Security", u"max-age=31536000")
        web.header(u"Content-Security-Policy", u"default-src 'none'; img-src 'self'; style-src 'self'")
        web.header(u"X-Frame-Options", u"DENY")
        web.header(u"Cache-Control", u"no-cache, no-store, max-age=0, s-maxage=0, must-revalidate")
        web.header(u"Expires", u"0")
 
        input_from_user = web.input(username=u"nobody", current_password=u"none", 
                                    new_password=u"none", new_password_second=u"none")

        username = u"%s" % (input_from_user.username)
        current_password = u"%s" % (input_from_user.current_password)
        new_password = u"%s" % (input_from_user.new_password)
        new_password_second = u"%s" % (input_from_user.new_password_second)

        # Check if all the fields and hence variables are filled out by the user.
        if (not username or 
            not current_password or 
            not new_password or 
            not new_password_second):
            raise web.seeother (u'/')

        # Make sure that the user's input is not malicious
        valid_input, msg_to_web = basic_input_test(
            username, current_password, new_password, new_password_second)

        if not valid_input:
            return render.index(result = msg_to_web, args = get_html_text())

        # Authenticate the user
        authenticated_user, auth_username, msg_to_web = authenticate_user(username, current_password)

        if not authenticated_user:
            return render.index(result = msg_to_web, args = get_html_text())

        # Check if the new password is considered valid 
        valid_new_password, msg_to_web = password_input_test(
            auth_username, current_password, new_password)

        if not valid_new_password:
            return render.index(result = msg_to_web, args = get_html_text())

        # execute smbpasswd in order to change password
        msg_to_web = change_password(auth_username, current_password, new_password)

        return render.index(result = msg_to_web, args = get_html_text())

if __name__ == "__main__":
    app.run()
