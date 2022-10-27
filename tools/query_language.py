from sqlalchemy import or_, and_
import sqlalchemy
from sqlalchemy.ext.declarative import DeclarativeMeta
#from .exceptions import TableNotFoundError
from inspect import signature
import types

OPERATORS = {'equal': lambda f, a: f.__eq__(a),
             'not_equal': lambda f, a: f.__ne__(a),
             'less': lambda f, a: f.__lt__(a),
             'greater': lambda f, a: f.__gt__(a),
             'less_or_equal': lambda f, a: f.__le__(a),
             'greater_or_equal': lambda f, a: f.__ge__(a),
             'in': lambda f, a: f.in_(a),
             'not_in': lambda f, a: f.notin_(a),
             'ends_with': lambda f, a: f.like('%' + a),
             'begins_with': lambda f, a: f.like(a + '%'),
             'contains': lambda f, a: f.like('%' + a + '%'),
             'not_contains': lambda f, a: f.notlike('%' + a + '%'),
             'not_begins_with': lambda f, a: f.notlike(a + '%'),
             'not_ends_with': lambda f, a: f.notlike('%' + a),
             'is_empty': lambda f: f.__eq__(''),
             'is_not_empty': lambda f: f.__ne__(''),
             'is_null': lambda f: f.is_(None),
             'is_not_null': lambda f: f.isnot(None),
             'between': lambda f, a: f.between(a[0], a[1])
             }


class Filter(object):

    def __init__(self, models, query, operators=None):
        if isinstance(models, types.ModuleType):
            model_dict = {}
            for attr in models.__dict__.values():
                if isinstance(attr, DeclarativeMeta):
                    try:
                        table = sqlalchemy.inspect(attr).mapped_table
                        model_dict[table.name] = attr
                    except sqlalchemy.exc.NoInspectionAvailable:
                        pass
            self.models = model_dict
        else:
            self.models = dict(models)
        print(self.models)
        self.query = query
        self.operators = operators if operators else OPERATORS

    def querybuilder(self, rules):
        query, cond_list = self._make_query(self.query, rules)
        if rules['condition'] == 'OR':
            operator = or_
        elif rules['condition'] == 'AND':
            operator = and_
        return query.filter(operator(*cond_list))

    def _make_query(self, query, rules):
        cond_list = []
        for cond in rules['rules']:
            if 'condition' not in cond:
                operator = cond['operator']
                if operator not in OPERATORS:
                    raise NotImplementedError
                try:
                    model = self.models[cond['field'].split('.')[0]]
                except KeyError:
                    raise TableNotFoundError(cond['field'].split('.')[0])
                for table in query.column_descriptions:
                   if table['entity'] == model:
                       break
                else:
                    query = query.add_entity(model)
                field = getattr(model, cond['field'].split('.')[1])
                function = OPERATORS[operator]
                arity = len(signature(function).parameters)
                if arity == 1:
                    cond_list.append(function(field))
                elif arity == 2:
                    cond_list.append(function(field, cond['value']))
            else:
                query, cond_subrule = self._make_query(query, cond)
                if cond["condition"] == "OR":
                    operator = or_
                else:
                    operator = and_
                cond_list.append(operator(*cond_subrule))
        return query, cond_list

import re

_tokenizer = re.compile(r'\s*([()]|\b(?:or|and)\b)\s*').split
def tokenize(s):
    return filter(None, _tokenizer(s))

def parse_conditions(expr):
    stack = []  # or a `collections.deque()` object, which is a little faster
    top = items = []
    for token in tokenize(expr):
        if token == '(':
            stack.append(items)
            items.append([])
            items = items[-1]
        elif token == ')':
            if not stack:
                raise ValueError("Unbalanced parentheses")
            items = stack.pop()
        else:
            items.append(token)
    if stack:
        raise ValueError("Unbalanced parentheses")
    return top
