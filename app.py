from website import create_app
from website import views
if __name__ == "__main__":	
    app = create_app()

    app.run(debug=True)

