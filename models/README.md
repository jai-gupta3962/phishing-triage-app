# Trained model

The repository includes the trained text classification pipeline used by the application:

    models/nlp_pipeline.joblib

The application loads this model for NLP-based phishing risk analysis.

If the model is retrained with `train_model.py`, the generated pipeline is saved to the same path.
