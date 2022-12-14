from flask import current_app
from flask_script import Command
from app.models import *
from app import db
import datetime

class InitDbCommand(Command):
    """ Initialize the database."""

    def run(self):
        init_db()
        print('[INFO] Database has been initialized.')

def init_db():
    """ Initialize the database."""
    db.drop_all()
    db.create_all()
    create_default_tenant_and_group()
    create_default_users()

def create_default_tenant_and_group():
    if not Tenant.query.filter(Tenant.name == current_app.config['DEFAULT_TENANT_LABEL']).first():
        tenant = Tenant(name=current_app.config['DEFAULT_TENANT_LABEL'])
        db.session.add(tenant)
        db.session.commit()
        Group.add(tenant.id, label=current_app.config['DEFAULT_GROUP_LABEL'], default=True)
    return True

def create_default_users():
    """ Create users """
    default_user = current_app.config.get("DEFAULT_EMAIL","admin@example.com")
    default_password = current_app.config.get("DEFAULT_PASSWORD","admin")
    tenant = Tenant.query.filter(Tenant.name == current_app.config['DEFAULT_TENANT_LABEL']).first()
    if not User.query.filter(User.email == default_user).first():
        user = User.add(
            default_user,
            password=default_password,
            confirmed=True,
            tenant_id=tenant.id,
            roles=["Admin"],
            create_role=True
        )
    return True
