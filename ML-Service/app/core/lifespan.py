"""
FastAPI lifespan handler - loads the ML model on startup.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.services.model_service import model_service
import logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    logger.info("Starting ML Threat Detection Service...")
    model_service.load_model()
    logger.info("Model loaded. Service ready.")
    yield
    logger.info("Shutting down ML Threat Detection Service.")