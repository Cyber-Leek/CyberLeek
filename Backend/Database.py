from sqlalchemy import create_engine, Column, Integer, String, Float, Text
from sqlalchemy.orm import declarative_base, sessionmaker


# SQLite database file
DATABASE_URL = "sqlite:///./nids.db"


# Create database engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)


# Create database sessions
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


# Base class for database tables
Base = declarative_base()


# Incident table
class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)

    prediction = Column(String)
    confidence = Column(Float)
    attack_type = Column(String)
    risk = Column(String)

    evidence = Column(Text)
    explanation = Column(Text)

    feedback = Column(String)


# Create the table automatically
Base.metadata.create_all(bind=engine)