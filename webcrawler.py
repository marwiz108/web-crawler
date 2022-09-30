#!/usr/bin/env python
import argparse
import socket
import ssl
import sys

from parser import Parser

'''
The main web crawler program that connects to the server using a socket.
This program is responsible for sending requests to the fakebook server, and crawls
through all the links on the website to look for 5 secret flags.
'''
USERNAME = sys.argv[-2]
PASSWORD = sys.argv[-1]
BUFFER_LEN = 4096
HOST = "project2.5700.network"
PORT = 443
FORMAT = "utf-8"

def create_connection():
    '''
    Function:   create_connection - establishes an ssl socket connection to the host server
    Parameters: none
    Returns:    the socket connection, or terminates the program if connection is not successful
    '''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.create_default_context()
        s = context.wrap_socket(s, server_hostname=HOST)
        s.connect((HOST, PORT))
    except:
        sys.exit("Cannot establish socket connection")
    return s

def get_request_message(url, csrf_token, session_id):
    '''
    Function:   get_request_message - builds the http GET request message to send to the connection
    Parameters: url - the url destination of the request
                csrf_token - the csrf token needed to access the different pages
                session_id - the session id given to maintain the connection
    Returns:    a string of the GET request message headers that will be sent
    '''
    method_header = f"GET {url} HTTP/1.1"
    host_header = f"Host: {HOST}"
    cookies_header = f"Cookie: csrftoken={csrf_token}; sessionid={session_id}\r\n\r\n"
    return "\r\n".join((method_header, host_header, cookies_header))

def get_headers(raw_headers):
    '''
    Function:   get_headers - creates a dictionary of the headers returned in the http response
    Parameters: raw_headers - the raw headers returned from the http response
    Returns:    a dictionary of the headers with headers as the key and their data as values
    '''
    headers = {}
    for header in raw_headers[1:]:
        item = header.split(": ")
        if (item[0] in headers.keys()):
            headers[item[0]] = headers.get(item[0]) + "\n" + item[1]
        else:
            headers[item[0]] = item[1]
    return headers

def get_response_status(status_header):
    '''
    Function:   get_response_status - returns the http status code from the header
    Parameters: status_header - the header line containing the http info
    Returns:    the http status code number
    '''
    status = status_header.split()[1]

    if (status in ["200", "301", "302", "403", "404", "500", "503"]):
        return int(status)
    elif ("<title>Fakebook</title>" in status_header):
        return 200
    elif ("503" in status_header):
        return 503

def get_login_token(connection):
    '''
    Function:   get_login_token - sends GET request to the login page and retrieves the csrf token
    Parameters: connection - the socket connection that sends/receives requests/responses
    Returns:    the csrf token from the Set-Cookie header
    '''
    # login GET request
    get_login = get_request_message("/accounts/login/", "", "")
    # send request
    connection.sendall(get_login.encode(FORMAT))
    # get request response
    response = connection.recv(BUFFER_LEN).decode(FORMAT)
    # split response by headers and body
    request_response = response.split("\r\n\r\n")
    response_headers = request_response[0].split("\r\n")
    response_body = request_response[1] if len(request_response) == 2 else ''
    # parse headers dict
    headers = get_headers(response_headers)
    # get csrf token
    cookie = headers["Set-Cookie"]
    csrf = cookie[cookie.index("csrftoken=")+len("csrftoken="):cookie.index(";")]
    return csrf

def login_post_request(csrf_token):
    '''
    Function:   login_post_request - builds the login http POST request to send to the connection
    Parameters: csrf_token - the csrf token needed to send with the request
    Returns:    a string of the POST request message headers that will be sent
    '''
    # content/params
    form_data = f"username={USERNAME}&password={PASSWORD}&csrfmiddlewaretoken={csrf_token}&next=%2Ffakebook%2F\r\n\r\n"
    # headers
    method_header = "POST /accounts/login/?next=/fakebook/ HTTP/1.1"
    host_header = f"Host: {HOST}"
    content_length = f"Content-Length: {len(form_data)}"
    content_type = "Content-Type: application/x-www-form-urlencoded"
    csrf_header = f"Cookie: csrftoken={csrf_token}"
    # request message
    return "\r\n\r\n".join(("\r\n".join((method_header, host_header, content_length, content_type, csrf_header)), form_data))

def crawl_next_url(parser):
    '''
    Function:   crawl_next_url - goes through list of urls_queued, retrieves the url for the
                                 subsequent GET messages, and moves urls from the queue into
                                 the list of urls_crawled
    Parameters: parser - the HTML parser object that contains the lists of urls queued and crawled
    Returns:    the url of the next link to visit
    '''
    while True:
        url = parser.urls_queued[0]
        # if it is a /fakebook/ url -> remove from queued, add to crawled
        if "/fakebook/" in url:
            parser.urls_queued.pop(0)
            parser.urls_crawled.add(url)
            break
        else: 
            parser.urls_queued.pop(0)
    return url

def main():
    # connect socket
    connection = create_connection()
    prev_url = ""
    csrf_token = ""
    session_id = ""
    status = 0
    parser = Parser()

    # go to login page and get csrf token
    csrf_token = get_login_token(connection)
    # login using token
    post_login_msg = login_post_request(csrf_token)
    # send POST request
    connection.sendall(post_login_msg.encode(FORMAT))
    # get request response
    response = connection.recv(BUFFER_LEN).decode(FORMAT)
    # split response by headers and body
    request_response = response.split("\r\n\r\n")
    response_headers = request_response[0].split("\r\n")
    response_body = request_response[1] if len(request_response) == 2 else ''
    # parse headers dict
    headers = get_headers(response_headers)
    # get new csrf token and session id
    cookie = headers["Set-Cookie"]
    csrf_token = cookie[cookie.index("csrftoken=")+len("csrftoken="):cookie.index(";")]
    session_id = cookie[cookie.index("sessionid=")+len("sessionid="):cookie.index(";", cookie.index("sessionid="))]

    while True:
        # get response status
        status = get_response_status(response_headers[0])

        # handle status codes
        if status == 200:
            # parse html
            parser.feed(response_body)
            # crawl rest of the urls
            next_url = crawl_next_url(parser)
            prev_url = next_url
            request_msg = get_request_message(next_url, csrf_token, session_id)

        elif status == 301 or status == 302:
            # get new location url
            redirect_url = headers["Location"]
            redirect_url = redirect_url.replace("%0D%0A%0D%0A", "")
            # build new GET request message
            request_msg = get_request_message(redirect_url, csrf_token, session_id)

        elif status == 403 or status == 404:
            # ignore and crawl rest of the urls
            next_url = crawl_next_url(parser)
            prev_url = next_url
            request_msg = get_request_message(next_url, csrf_token, session_id)

        elif status == 500 or status == 503:
            # keep retrying request
            request_msg = get_request_message(prev_url, csrf_token, session_id)

        # send request
        connection.sendall(request_msg.encode(FORMAT))
        # get response
        response = connection.recv(BUFFER_LEN).decode(FORMAT)
        # split response by headers and body
        request_response = response.split("\r\n\r\n")
        response_headers = request_response[0].split("\r\n")
        response_body = request_response[1] if len(request_response) == 2 else ''
        # parse headers dict
        headers = get_headers(response_headers)
        # get new csrf token and session id
        if ("Set-Cookie" in headers):
            cookie = headers["Set-Cookie"]
            if ("csrftoken=" in cookie):
                csrf_token = cookie[cookie.index("csrftoken=")+len("csrftoken="):cookie.index(";")]
            if ("sessionid=" in cookie):
                session_id = cookie[cookie.index("sessionid=")+len("sessionid="):cookie.index(";", cookie.index("sessionid="))]

        if len(parser.secret_flags) == 5:
            break

        # close and reconnect if 'Connection: close' received from response
        if "Connection" in headers.keys() and headers["Connection"] == "close":
            connection.close()
            connection = create_connection()

    print("\n".join(parser.secret_flags))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("USERNAME", type=str, action="store", help="USERNAME")
    parser.add_argument("PASSWORD", type=str, action="store", help="PASSWORD")
    args = parser.parse_args()
    main()
