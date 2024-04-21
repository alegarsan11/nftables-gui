import hug
import tables, chains, rules

api = hug.API(__name__)
api.extend(tables, '/tables')
api.extend(chains, '/chains')
api.extend(rules, '/rules')
