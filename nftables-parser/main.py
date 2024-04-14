import hug
import tables

api = hug.API(__name__)
api.extend(tables, '/tables')
