from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy import func,and_,or_,not_
from app.utils.mixin_models import LogMixin,DateMixin
from flask_login import UserMixin
from app.utils import jquery_filters
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from datetime import datetime, timedelta
from app import db, login
from uuid import uuid4
from app.utils import misc
import arrow
import json
import os

class Tenant(LogMixin,db.Model):
    __tablename__ = 'tenants'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    token = db.Column(db.String,  default=lambda: uuid4().hex, unique=True)
    name = db.Column(db.String(64), unique=True)
    contact_email = db.Column(db.String())
    license = db.Column(db.String())
    users = db.relationship('User', backref='tenant', lazy='dynamic')
    groups = db.relationship('Group', backref='tenant', lazy='dynamic')
    tags = db.relationship('Tag', backref='tenant', lazy='dynamic')
    agents = db.relationship('Agent', backref='tenant', lazy='dynamic')
    policies = db.relationship('Policy', backref='tenant', lazy='dynamic')
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def register_agent(self, data):
        data["key"] = uuid4().hex
        data["last_active"] = datetime.utcnow()
        agent = Agent(**data)

        # add to tenant
        self.agents.append(agent)

        # add to default group
        if default_group := self.default_group():
            agent.groups.append(default_group)

        # if install group is specified
        if install_group := data.get("install_group"):
            if found_group := self.groups.filter(func.lower(Group.label) == install_group.lower()).first():
                agent.groups.append(found_group)

        db.session.add(agent)
        db.session.commit()
        return data["key"]

    def default_group(self):
        return self.groups.filter(Group.default == True).first()

    def generate_token(self, agent_id):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({ 'agent_id': agent_id, 'tenant': self.token}).decode('utf-8')

    def verify_token(self, token, get_agent=False):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            current_app.logger.warning("SignatureExpired for token")
            return None # valid token, but expired
        except BadSignature:
            current_app.logger.warning("BadSignature for token")
            return None # invalid token
        if get_agent:
            return Agent.query.filter(Agent.key == data["agent_id"]).first()
        return True

class ComplianceTaskResults(db.Model):
    __tablename__ = 'compliance_task_results'
    id = db.Column(db.Integer(), primary_key=True,autoincrement=True)
    validate = db.Column(db.String())
    enforce = db.Column(db.String())
    validate_rtn_code = db.Column(db.Integer, default=0)
    enforce_rtn_code = db.Column(db.Integer, default=None)
    task_id = db.Column(db.Integer, db.ForeignKey('compliance_tasks.id'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def failed(self):
        if self.enforce_failed():
            return True
        if self.validate_failed() and self.enforce_rtn_code is None:
            return True
        return False

    def validate_failed(self):
        return self.validate_rtn_code != 0

    def enforce_failed(self):
        """
        if enforce_rtn_code is None, policy did not have enforcement action
        so it doesnt get counted as failed
        """
        code = self.enforce_rtn_code or 0
        if code > 0:
            return True
        return False

class ComplianceTask(db.Model):
    __tablename__ = 'compliance_tasks'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    name = db.Column(db.String(), nullable=False)
    label = db.Column(db.String(), nullable=False)
    interval = db.Column(db.Integer, default=300)
    timeout = db.Column(db.Integer, nullable=False, default=10)
    validate = db.Column(db.JSON, nullable=False, default={})
    enforce = db.Column(db.JSON, nullable=False, default={})
    validation_enabled = db.Column(db.Boolean, default=True)
    enforcement_enabled = db.Column(db.Boolean, default=False)
    results = db.relationship('ComplianceTaskResults', backref='task', lazy='dynamic')
    tags = db.relationship('Tag', secondary='compliance_tags', lazy='dynamic',
                            backref=db.backref('compliance_tasks', lazy='dynamic'))
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    @staticmethod
    def add(tenant_id, label=None):
        name = uuid4().hex
        if not label:
            label = name
        task = ComplianceTask(label=label, name=name, tenant_id=tenant_id)
        db.session.add(task)
        db.session.commit()
        return task

    def generate(self):
        """
        format request for the agent
        """
        if not self.validation_enabled:
            return {}
        return {
            "uuid":self.name,
            "label":self.label,
            "interval":self.interval,
            "timeout": self.timeout,
            "validate": self.validate if self.validation_enabled else {},
            "enforce": self.enforce if self.enforcement_enabled else {},
        }

    def set_tags_by_name(self,tags):
        if not isinstance(tags,list):
            tags = [tags]
        ComplianceTags.query.filter(ComplianceTags.compliance_id == self.id).delete()
        for tag in tags:
            if found := Tag.find_by_name(tag):
                self.tags.append(found)
        db.session.commit()
        return True

    def get_tags_for_form(self):
        tags = {}
        enabled_tags = self.tags.all()
        for tag in Tag.query.all():
            if tag in enabled_tags:
                tags[tag] = True
            else:
                tags[tag] = False
        return tags

    def unique_agent_count(self, days=7):
        time_ago = datetime.utcnow() - timedelta(days=days)
        return self.results.filter(ComplianceTaskResults.date_added > time_ago).distinct(ComplianceTaskResults.agent_id).count()

    def get_compliance_validation_percentage(self, days=7):
        time_ago = datetime.utcnow() - timedelta(days=days)
        _query = self.results.filter(ComplianceTaskResults.date_added > time_ago).distinct(ComplianceTaskResults.agent_id).order_by(ComplianceTaskResults.agent_id,ComplianceTaskResults.id.desc())
        total_results = _query.count()
        if not total_results:
            return 0
        success = _query.filter(ComplianceTaskResults.validate_rtn_code == 0).count()
        return round((success/total_results)*100)

    def get_compliance_enforcement_percentage(self, days=7):
        time_ago = datetime.utcnow() - timedelta(days=days)
        _query = self.results.filter(ComplianceTaskResults.date_added > time_ago).distinct(ComplianceTaskResults.agent_id).order_by(ComplianceTaskResults.agent_id,ComplianceTaskResults.id.desc())
        total_results = _query.count()
        if not total_results:
            return 0
        success = _query.filter(or_(ComplianceTaskResults.enforce_rtn_code == 0, ComplianceTaskResults.enforce_rtn_code == None)).count()
        return round((success/total_results)*100)

class PolicyComplianceTask(db.Model):
    __tablename__ = 'policy_compliance_tasks'
    id = db.Column(db.Integer(), primary_key=True)
    task_id = db.Column(db.Integer(), db.ForeignKey('compliance_tasks.id', ondelete='CASCADE'))
    policy_id = db.Column(db.Integer(), db.ForeignKey('policies.id', ondelete='CASCADE'))

class Policy(db.Model):
    __tablename__ = 'policies'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    name = db.Column(db.String(), nullable=False)
    label = db.Column(db.String(), nullable=False)
    headers = db.Column(db.JSON(), default={})
    url = db.Column(db.String())
    collection_tasks = db.Column(db.JSON(), default=[])
    compliance_tasks = db.relationship('ComplianceTask', secondary='policy_compliance_tasks', lazy='dynamic')
    groups = db.relationship('Group', backref='policy', lazy='dynamic')
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def generate(self):
        if self.headers:
            try:
                headers = json.loads(self.headers)
            except:
                headers = {}
        else:
            headers = {}
        collection_tasks = [
            {"name":"get-performance","url":"","headers":{},"get":5,"post":160,"hash_fields":[],"table":"performance"},
            {"name":"get-disk","url":"","headers":{},"get":3600,"post":1800,"hash_fields":["mount"],"table":"disk"}
        ]
        config = {
            "uuid": self.name,
            "label": self.label,
            "collection":{
                "url":self.url or None,
                "headers":headers,
                "tasks":collection_tasks
            },
            "compliance":{
                "url":self.url or None,
                "headers":headers,
                "tasks":[]
            }
        }
        for task in self.compliance_tasks.all():
            task_json = task.generate()
            if task_json:
                config["compliance"]["tasks"].append(task_json)
        return config

    @staticmethod
    def add(tenant_id, label=None):
        name = uuid4().hex
        if not label:
            label = name
        policy = Policy(label=label, name=name, tenant_id=tenant_id)
        db.session.add(policy)
        db.session.commit()
        return policy

class Group(LogMixin,db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    name = db.Column(db.String(), nullable=False)
    label = db.Column(db.String())
    default = db.Column(db.Boolean, default=False)
    precedence = db.Column(db.Integer, default=10)
    policy_id = db.Column(db.Integer, db.ForeignKey('policies.id'))
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    @staticmethod
    def add(tenant_id, label=None, default=False):
        name = uuid4().hex
        if not label:
            label = name
        group = Group(label=label, name=name, tenant_id=tenant_id, default=default)
        db.session.add(group)
        db.session.commit()
        return group

    def as_dict(self,fields=[]):
        data = {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}
        data["agent_count"] = self.agents.count()
        data["has_policy"] = True if self.policy else False
        data["group_ref"] = f"/groups/{self.id}"
        if fields:
            temp = {}
            for key,value in data.items():
                if key in fields:
                    temp[key] = value
            return temp
        return data

class AgentsGroups(db.Model):
    __tablename__ = 'agents_groups'
    id = db.Column(db.Integer(), primary_key=True)
    agent_id = db.Column(db.Integer(), db.ForeignKey('agents.id', ondelete='CASCADE'))
    group_id = db.Column(db.Integer(), db.ForeignKey('groups.id', ondelete='CASCADE'))

class ComplianceTags(db.Model):
    __tablename__ = 'compliance_tags'
    id = db.Column(db.Integer(), primary_key=True)
    compliance_id = db.Column(db.Integer(), db.ForeignKey('compliance_tasks.id', ondelete='CASCADE'))
    tag_id = db.Column(db.Integer(), db.ForeignKey('tags.id', ondelete='CASCADE'))

class AgentTags(db.Model):
    __tablename__ = 'agent_tags'
    id = db.Column(db.Integer(), primary_key=True)
    agent_id = db.Column(db.Integer(), db.ForeignKey('agents.id', ondelete='CASCADE'))
    tag_id = db.Column(db.Integer(), db.ForeignKey('tags.id', ondelete='CASCADE'))

class Agent(db.Model):
    __tablename__ = "agents"
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    key = db.Column(db.String()) # agent_id
    token = db.Column(db.String,  default=lambda: uuid4().hex, unique=True)
    version = db.Column(db.String(), default="1.0.0")
    enabled = db.Column(db.Boolean, server_default='1')
    install_group = db.Column(db.String())
    public_addr = db.Column(db.String)
    country_code = db.Column(db.String())
    country_name = db.Column(db.String())
    region_name = db.Column(db.String())
    city_name = db.Column(db.String())
    lat = db.Column(db.Float)
    long = db.Column(db.Float)
    uninstall = db.Column(db.Boolean, server_default='0')
    cpu_count = db.Column(db.Integer, default=0)
    logical_cpu_count = db.Column(db.Integer, default=0)
    memory = db.Column(db.String())
    #// Base
    hostname = db.Column(db.String())
    fqdn = db.Column(db.String())
    domain = db.Column(db.String())
    forest = db.Column(db.String())
    dn = db.Column(db.String())
    site = db.Column(db.String())
    domain_joined = db.Column(db.Boolean, server_default='0')
    is_dc = db.Column(db.Boolean, server_default='0')
    family = db.Column(db.String()) #windows
    release = db.Column(db.String()) #10
    sys_version = db.Column(db.String()) #1903
    install_type = db.Column(db.String())
    edition = db.Column(db.String())
    build = db.Column(db.String())
    machine = db.Column(db.String()) #amd64
    local_addr = db.Column(db.String())
    memory = db.Column(db.String())
    processor = db.Column(db.String())
    last_boot = db.Column(db.DateTime)
    last_active = db.Column(db.DateTime)
    svc_start = db.Column(db.DateTime)
    svc_uptime = db.Column(db.Integer)
    uptime = db.Column(db.Float)
    groups = db.relationship('Group', secondary='agents_groups', lazy='dynamic',
                            backref=db.backref('agents', lazy='dynamic'))
    tags = db.relationship('Tag', secondary='agent_tags', lazy='dynamic',
                            backref=db.backref('agents', lazy='dynamic'))
    compliance_results = db.relationship('ComplianceTaskResults', backref='agent', lazy='dynamic')
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

    @staticmethod
    def find(key):
        return Agent.query.filter(Agent.key == key).first()

    def humanize_last_active(self):
        if not self.last_active:
            return "Never"
        diff = arrow.utcnow() - arrow.get(self.last_active)
        hours,remainder = divmod(diff.seconds,3600)
        minutes,seconds = divmod(remainder,60)
        return f"{hours}h:{minutes}m:{seconds}s"

    def as_dict(self,fields=[]):
        data = {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}
        data["last_active_h"] = self.humanize_last_active()
        data["groups"] = [group.label for group in self.groups.all()]
        data["tags"] = [tag.name for tag in self.tags.all()]
        data["agent_ref"] = f"/agents/{self.key}"
        if fields:
            temp = {}
            for key,value in data.items():
                if key in fields:
                    temp[key] = value
            return temp
        return data

    @staticmethod
    def jquery_format():
        filters = []
        restricted_fields = []
        for col in Agent.__table__.columns:
            if col.name not in restricted_fields:
                #col.name,col.type
                filter = jquery_filters.create_filter(col.type, f"agents.{col.name}", col.name)
                if filter:
                    # edit the filter
                    filters.append(filter)
        return filters

    def total_agents(self, as_query=False, hours=None, as_count=False, tenant_id=None):
        _query = self.agents
        if hours:
            dt = datetime.utcnow() - timedelta(hours=hours)
            _query = _query.filter(Agent.last_active > dt)
        if tenant_id:
            _query = _query.filter(Agent.tenant_id == tenant_id)
        if as_query:
            return _query
        if as_count:
            return _query.count()
        return _query.all()

    @staticmethod
    def _query(id=None,date_added=None,last_active=None,enabled=None,tags=[],fqdn=None,key=None,
        tenant_id=None,date_sort="gt",limit=50,as_query=False,as_json=False,as_count=False,fields=[],family=None,
        groups=None):
        data = []
        _query = Agent.query
        if id:
            _query = _query.filter(Agent.id == id)
        if enabled:
            _query = _query.filter(Agent.enabled == enabled)
        if key:
            search = "%{}%".format(key)
            _query = _query.filter(Agent.key.ilike(search))
        if groups:
            for group in groups:
                _query = _query.filter(Agent.groups.any(name=group.lower()))
        if family:
            search = "%{}%".format(family)
            _query = _query.filter(Agent.family.ilike(search))
        if fqdn:
            search = "%{}%".format(fqdn)
            _query = _query.filter(Agent.fqdn.ilike(search))
        if tenant_id:
            _query = _query.filter(Agent.tenant_id == tenant_id)
        if tags:
            for tag in tags:
                _query = _query.filter(Agent.tags.any(name=tag.lower()))
        if last_active:
            dt = datetime.utcnow() - timedelta(hours=last_active)
            if date_sort != "gt":
                _query = _query.filter(Agent.last_active <= dt)
            else:
                _query = _query.filter(Agent.last_active >= dt)
        if date_added:
            dt = arrow.get(date_added).datetime
            if date_sort != "gt":
                _query = _query.filter(FilePermission.date_added <= dt)
            else:
                _query = _query.filter(FilePermission.date_added >= dt)
        if as_json:
            for record in _query.all():
                data.append(record.as_dict(fields=fields))
            return data
        if as_query:
            return _query
        if as_count:
            return _query.count()
        return _query.all()

    def primary_group(self):
        return self.groups.order_by(Group.precedence.asc()).first()

    def policy(self):
        group = self.primary_group()
        if not group:
            return False
        return group.policy

    def policy_format(self):
        policy = self.policy()
        if not policy:
            return {}
        return policy.generate()

    def latest_result_for_compliance_task(self, task_id):
        return self.compliance_results.filter(ComplianceTaskResults.task_id == task_id).order_by(ComplianceTaskResults.id.desc()).first()

    def get_compliance_results_validate_percentage(self):
        validate_rtn_results = self.compliance_results.with_entities(ComplianceTaskResults.validate_rtn_code,func.count(ComplianceTaskResults.validate_rtn_code)).group_by(ComplianceTaskResults.validate_rtn_code).all()
        for record in validate_rtn_results:
            rtn_code, rtn_code_count = record
        pass

    def compliance_tasks(self):
        policy = self.policy()
        if not policy:
            return []
        return policy.compliance_tasks.all()

    def get_compliance_validation_percentage(self, task_id=None, days=7, history=False):
        time_ago = datetime.utcnow() - timedelta(days=days)
        _query = self.compliance_results.filter(ComplianceTaskResults.date_added > time_ago)
        if task_id:
            _query = _query.filter(ComplianceTaskResults.task_id == task_id)
        if not history:
            task_id_list = [x.id for x in self.compliance_tasks()]
            _query = _query.filter(ComplianceTaskResults.task_id.in_(task_id_list))
        total_results = _query.count()
        if not total_results:
            return 0
        success = _query.filter(ComplianceTaskResults.validate_rtn_code == 0).count()
        return round((success/total_results)*100)

    def get_compliance_enforcement_percentage(self, task_id=None, days=7, history=False):
        time_ago = datetime.utcnow() - timedelta(days=days)
        _query = self.compliance_results.filter(ComplianceTaskResults.date_added > time_ago)
        if task_id:
            _query = _query.filter(ComplianceTaskResults.task_id == task_id)
        if not history:
            task_id_list = [x.id for x in self.compliance_tasks()]
            _query = _query.filter(ComplianceTaskResults.task_id.in_(task_id_list))
        total_results = _query.count()
        if not total_results:
            return 0
        success = _query.filter(or_(ComplianceTaskResults.enforce_rtn_code == 0, ComplianceTaskResults.enforce_rtn_code == None)).count()
        return round((success/total_results)*100)

class User(LogMixin,db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    is_active = db.Column(db.Boolean(), nullable=False, server_default='1')
    email = db.Column(db.String(255), nullable=False, unique=True)
    username = db.Column(db.String(100), unique=True)
    email_confirmed_at = db.Column(db.DateTime())
    password = db.Column(db.String(255), nullable=False, server_default='')
    last_password_change = db.Column(db.DateTime())
    first_name = db.Column(db.String(100), nullable=False, server_default='')
    last_name = db.Column(db.String(100), nullable=False, server_default='')
    roles = db.relationship('Role', secondary='user_roles')
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    @staticmethod
    def verify_auth_token(token):
        data = misc.verify_jwt(token)
        if data is False:
            return False
        return User.query.get(data['id'])

    def generate_auth_token(self, expiration=600):
        data = {'id': self.id}
        return misc.generate_jwt(data, expiration)

    @staticmethod
    def verify_invite_token(token):
        data = misc.verify_jwt(token)
        if data is False:
            return False
        return data["email"]

    @staticmethod
    def generate_invite_token(expiration=600):
        data = {'email': self.email}
        return misc.generate_jwt(data, expiration)

    def pretty_roles(self):
        data = []
        for role in self.roles:
            data.append(role.name.lower())
        return data

    def can_edit_roles(self):
        return "admin" in self.pretty_roles()

    def has_role(self,roles):
        '''checks if user has any of the listed roles'''
        if not roles:
            return False
        if not isinstance(roles,list) and not isinstance(roles,tuple):
            roles = [roles]
        my_roles = self.pretty_roles()
        for role in roles:
            if role.lower() in my_roles:
                return True
        return False

    def has_roles(self,roles):
        '''checks if user has all of the listed roles'''
        if not roles:
            return False
        if not isinstance(roles,list) and not isinstance(roles,tuple):
            roles = [roles]
        my_roles = self.pretty_roles()
        for role in roles:
            if role.lower() not in my_roles:
                return False
        return True

    def set_roles_by_name(self,roles):
        #roles = ["Admin","Another Role"]
        if not isinstance(roles,list):
            roles = [roles]
        new_roles = []
        for role in roles:
            found = Role.find_by_name(role)
            if found:
                new_roles.append(found)
        self.roles[:] = new_roles
        db.session.commit()
        return True

    def get_roles_for_form(self):
        roles = {}
        for role in Role.query.all():
            if role in self.roles:
                roles[role] = True
            else:
                roles[role] = False
        return roles

    def set_password(self, password):
        self.password = generate_password_hash(password, method='sha256')
        self.last_password_change = str(datetime.utcnow())

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Tag(LogMixin,db.Model):
    __tablename__ = 'tags'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(), unique=True)
    color = db.Column(db.String(), default="blue")
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    @staticmethod
    def find_by_name(name):
        tag_exists = Tag.query.filter(func.lower(Tag.name) == func.lower(name)).first()
        if tag_exists:
            return tag_exists
        return False

    @staticmethod
    def add(tenant_id, name):
        if Tag.find_by_name(name):
            return True
        tag = Tag(name=name,tenant_id=tenant_id)
        db.session.add(tag)
        db.session.commit()
        return tag

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)

    @staticmethod
    def find_by_name(name):
        return Role.query.filter(func.lower(Role.name) == func.lower(name)).first()

class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))

class ConfigStore(db.Model,LogMixin):
    __tablename__ = 'config_store'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    key = db.Column(db.String())
    value = db.Column(db.String())
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    @staticmethod
    def find(key):
        return ConfigStore.query.filter(ConfigStore.key == key).first()

    @staticmethod
    def upsert(key,value):
        found = ConfigStore.find(key)
        if found:
            found.value = value
            db.session.commit()
        else:
            c=ConfigStore(key=key,value=value)
            db.session.add(c)
            db.session.commit()
        return True

class Logs(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    namespace = db.Column(db.String(),nullable=False,default="general")
    log_type = db.Column(db.String(),nullable=False,default="info")
    message = db.Column(db.String(),nullable=False)
    meta = db.Column(db.JSON(),default="[]")
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    @staticmethod
    def add_log(message,log_type="info",namespace="general",meta={}):
        if log_type.lower() not in ["info","warning","error","critical"]:
            return False
        msg = Logs(namespace=namespace.lower(),message=message,
            log_type=log_type.lower(),meta=meta)
        db.session.add(msg)
        db.session.commit()
        return True

    @staticmethod
    def get_logs(log_type=None,limit=100,as_query=False,span=None,as_count=False,paginate=False,page=1,namespace="general",meta={}):
        '''
        get_logs(log_type='error',namespace="my_namespace",meta={"key":"value":"key2":"value2"})
        '''
        _query = Logs.query.filter(Logs.namespace == namespace.lower()).order_by(Logs.id.desc())
        if log_type:
            if not isinstance(log_type,list):
                log_type = [log_type]
            _query = _query.filter(Logs.log_type.in_(log_type))

        if meta:
            for key,value in meta.items():
                _query = _query.filter(Logs.meta.op('->>')(key) == value)
        if span:
            _query = _query.filter(Logs.date_added >= arrow.utcnow().shift(hours=-span).datetime)
        if as_query:
            return _query
        if as_count:
            return _query.count()
        if paginate:
            return _query.paginate(page=page, per_page=10)
        return _query.limit(limit).all()

class Performance(db.Model):
    __tablename__ = "performance"
    id = db.Column(db.Integer, primary_key=True)
    cpu_load = db.Column(db.Float)
    cpu_load_per_core = db.Column(db.JSON(), default={})
    mem_total = db.Column(db.Float)
    mem_used = db.Column(db.Float)
    mem_free = db.Column(db.Float)
    mem_percent_used = db.Column(db.Float)
    mem_total_h = db.Column(db.String)
    mem_used_h = db.Column(db.String)
    mem_free_h = db.Column(db.String)
    swap_total = db.Column(db.Float)
    swap_used = db.Column(db.Float)
    swap_free = db.Column(db.Float)
    swap_percent_used = db.Column(db.Float)
    swap_total_h = db.Column(db.String)
    swap_used_h = db.Column(db.String)
    swap_free_h = db.Column(db.String)
    swapped_in = db.Column(db.Float)
    swapped_out = db.Column(db.Float)
    record_hash = db.Column(db.String)
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class AgentUser(db.Model):
    __tablename__ = "agent_users"
    id = db.Column(db.Integer, primary_key=True)
    local_account = db.Column(db.Boolean)
    username = db.Column(db.String())
    domain = db.Column(db.String())
    sid = db.Column(db.String())
    last_password_change = db.Column(db.DateTime)
    password_age = db.Column(db.Integer)
    priv = db.Column(db.Integer)
    comment = db.Column(db.String())
    flags = db.Column(db.Integer)
    useraccountcontrol = db.Column(db.String())
    script_path = db.Column(db.String())
    last_logon = db.Column(db.DateTime)
    last_logoff = db.Column(db.DateTime)
    acct_expires = db.Column(db.DateTime)
    bad_pw_count = db.Column(db.Integer)
    num_logons = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    primary_group_id = db.Column(db.Integer)
    password_expired = db.Column(db.Integer)
    groups = db.Column(db.JSON())
    account_type = db.Column(db.String())
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class AgentGroup(db.Model):
    __tablename__ = "agent_groups"
    id = db.Column(db.Integer, primary_key=True)
    members = db.Column(db.JSON())
    members_count = db.Column(db.Integer)
    domain_accounts = db.Column(db.Integer)
    local_account = db.Column(db.Boolean)
    group = db.Column(db.String())
    account_type = db.Column(db.String())
    description = db.Column(db.String())
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class AgentSoftware(db.Model):
    __tablename__ = "agent_softwares"
    id = db.Column(db.Integer, primary_key=True)
    publisher = db.Column(db.String())
    displayname = db.Column(db.String())
    installdate = db.Column(db.String())
    uninstallstring = db.Column(db.String())
    majorversion = db.Column(db.Integer)
    source = db.Column(db.String())
    installsource = db.Column(db.String())
    estimatedsize = db.Column(db.Integer)
    version = db.Column(db.String())
    displayversion = db.Column(db.String())
    modifypath = db.Column(db.String())
    description = db.Column(db.String())
    minorversion = db.Column(db.Integer)
    signed = db.Column(db.Boolean, server_default='0')
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class AgentDisk(db.Model):
    __tablename__ = "agent_disks"
    id = db.Column(db.Integer, primary_key=True)
    used_percent = db.Column(db.Integer)
    used = db.Column(db.String())
    mount = db.Column(db.String())
    free = db.Column(db.String())
    fs_type = db.Column(db.String())
    device = db.Column(db.String())
    total = db.Column(db.String())
    options = db.Column(db.String())
    record_hash = db.Column(db.String)
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class AgentMemory(db.Model):
    __tablename__ = "agent_memorys"
    id = db.Column(db.Integer, primary_key=True)
    used = db.Column(db.String())
    cache = db.Column(db.String())
    free = db.Column(db.String())
    shared = db.Column(db.String())
    total = db.Column(db.String())
    buffers = db.Column(db.String())
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class AgentNeighbor(db.Model):
    __tablename__ = "agent_neighbors"
    id = db.Column(db.Integer, primary_key=True)
    asset = db.Column(db.String())
    address = db.Column(db.String())
    mac = db.Column(db.String())
    type = db.Column(db.String())
    status = db.Column(db.String())
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class AgentScan(db.Model):
    __tablename__ = "agent_scans"
    id = db.Column(db.Integer, primary_key=True)
    asset = db.Column(db.String())
    address = db.Column(db.String())
    mac = db.Column(db.String())
    port = db.Column(db.Integer)
    service = db.Column(db.String())
    name = db.Column(db.String())
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class AgentSchTask(db.Model):
    __tablename__ = "agent_schtasks"
    id = db.Column(db.Integer, primary_key=True)
    last_result = db.Column(db.String())
    folder = db.Column(db.String())
    hidden = db.Column(db.Boolean)
    state = db.Column(db.String())
    last_run = db.Column(db.DateTime)
    enabled = db.Column(db.Boolean)
    next_run = db.Column(db.DateTime)
    sid = db.Column(db.String())
    username = db.Column(db.String())
    domain = db.Column(db.String())
    account_type = db.Column(db.String())
    hash = db.Column(db.String())
    command = db.Column(db.String())
    base_command = db.Column(db.String())
    image = db.Column(db.String())
    arguments = db.Column(db.String())
    run_level = db.Column(db.String())
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class AgentStartup(db.Model):
    __tablename__ = "agent_startups"
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String())
    image = db.Column(db.String())
    command = db.Column(db.String())
    location = db.Column(db.String())
    sid = db.Column(db.String())
    username = db.Column(db.String())
    domain = db.Column(db.String())
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class AgentShare(db.Model):
    __tablename__ = "agent_shares"
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String())
    allowmaximum = db.Column(db.Boolean)
    accessmask = db.Column(db.String())
    description = db.Column(db.String())
    installdate = db.Column(db.DateTime)
    caption = db.Column(db.String())
    maximumallowed = db.Column(db.String())
    path = db.Column(db.String())
    type = db.Column(db.String())
    wmi_class = db.Column(db.String())
    name = db.Column(db.String())
    type_str = db.Column(db.String())
    permissions = db.Column(db.String())
    passwd = db.Column(db.String())
    current_uses = db.Column(db.BigInteger)
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class AgentLogon(db.Model):
    __tablename__ = "agent_logons"
    id = db.Column(db.Integer, primary_key=True)
    local_account = db.Column(db.Boolean)
    account_type = db.Column(db.String())
    username = db.Column(db.String())
    logondomain = db.Column(db.String())
    domain = db.Column(db.String())
    authenticationpackage = db.Column(db.String())
    logontype = db.Column(db.String())
    sid = db.Column(db.String())
    logontime = db.Column(db.DateTime)
    logonid = db.Column(db.BigInteger)
    logonserver = db.Column(db.String())
    upn = db.Column(db.String())
    last_password_change = db.Column(db.DateTime)
    password_age = db.Column(db.Integer)
    priv = db.Column(db.Integer)
    comment = db.Column(db.String())
    flags = db.Column(db.Integer)
    useraccountcontrol = db.Column(db.String())
    script_path = db.Column(db.String())
    workstations = db.Column(db.String())
    last_logon = db.Column(db.DateTime)
    last_logoff = db.Column(db.DateTime)
    acct_expires = db.Column(db.DateTime)
    bad_pw_count = db.Column(db.Integer)
    num_logons = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    primary_group_id = db.Column(db.Integer)
    password_expired = db.Column(db.Integer)
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())

class AgentService(db.Model):
    __tablename__ = "agent_services"
    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.String())
    arguments = db.Column(db.String())
    registry_name = db.Column(db.String())
    service_type = db.Column(db.String())
    start_type = db.Column(db.String())
    dependencies = db.Column(db.JSON)
    display_name = db.Column(db.String())
    description = db.Column(db.String())
    command = db.Column(db.String())
    status = db.Column(db.String())
    hash = db.Column(db.String())
    username = db.Column(db.String())
    sid = db.Column(db.String())
    domain = db.Column(db.String())
    account_type = db.Column(db.String())
    agent_id = db.Column(db.Integer, db.ForeignKey('agents.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    date_added = db.Column(db.DateTime, server_default=func.now())
    date_updated = db.Column(db.DateTime, onupdate=func.now())



@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
