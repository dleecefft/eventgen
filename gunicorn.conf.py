import os


bind = f"0.0.0.0:{os.getenv('PORT', '8080')}"
workers = 1
threads = 4
timeout = 120
accesslog = "-"
errorlog = "-"
capture_output = True
