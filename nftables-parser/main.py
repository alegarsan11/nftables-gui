import hug
import tables, chains

api = hug.API(__name__)
api.extend(tables, '/tables')
api.extend(chains, '/chains')
