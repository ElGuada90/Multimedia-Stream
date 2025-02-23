import os
from supermovies import app   

if __name__ == '__main__':
    HOST = os.environ.get('SERVER_HOST', 'localhost')

    try:
        PORT = int(os.environ.get('SERVER_PORT', '1990'))
    except ValueError:
        PORT = 1990

    app.run(HOST, PORT, debug=True)
