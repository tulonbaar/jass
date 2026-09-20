import os
from jass.db.database import SessionLocal
from jass.db.models import SystemSetting

def get_setting(key: str, default: any = None) -> str:
    db = SessionLocal()
    try:
        setting = db.query(SystemSetting).filter_by(key=key).first()
        if setting and setting.value is not None:
            return setting.value
        
        # Fallback to .env / OS env
        env_val = os.getenv(key)
        val_to_save = env_val if env_val is not None else (str(default) if default is not None else "")
        
        # Save to DB so we don't rely on .env next time
        try:
            if setting:
                setting.value = val_to_save
            else:
                setting = SystemSetting(key=key, value=val_to_save)
                db.add(setting)
            db.commit()
        except Exception:
            pass # Ignore db errors on save
            
        return val_to_save
    except Exception:
        return os.getenv(key, str(default) if default is not None else "")
    finally:
        db.close()

def set_setting(key: str, value: str):
    db = SessionLocal()
    try:
        setting = db.query(SystemSetting).filter_by(key=key).first()
        if setting:
            setting.value = str(value)
        else:
            setting = SystemSetting(key=key, value=str(value))
            db.add(setting)
        db.commit()
    finally:
        db.close()
