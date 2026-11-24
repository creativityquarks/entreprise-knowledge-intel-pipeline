FROM apache/airflow:2.10.5-python3.12
USER root
RUN mkdir -p /opt/pipeline && chown -R airflow:root /opt/pipeline
USER airflow
RUN pip install --no-cache-dir 'poetry==1.8.5'
ENV POETRY_VIRTUALENVS_IN_PROJECT=true POETRY_NO_INTERACTION=1
WORKDIR /opt/pipeline
COPY --chown=airflow:root pyproject.toml /opt/pipeline/pyproject.toml
RUN poetry install --no-root --with dev
