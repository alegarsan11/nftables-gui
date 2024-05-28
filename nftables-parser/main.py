import hug
import tables, chains, rules, sets, maps, service

api = hug.API(__name__)
api.extend(tables, '/tables')
api.extend(chains, '/chains')
api.extend(rules, '/rules')
api.extend(sets, '/sets')
api.extend(maps, '/maps')
api.extend(service, '/service')
