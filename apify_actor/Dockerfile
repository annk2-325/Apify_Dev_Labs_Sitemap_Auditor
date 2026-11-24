FROM apify/actor-python:3.11

WORKDIR /usr/src/app

ENV PYTHONPATH=/usr/src/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY apify_actor/requirements.txt ./apify_actor/requirements.txt
RUN pip install --no-cache-dir -r apify_actor/requirements.txt

COPY core/ ./core/
COPY apify_actor/ ./apify_actor/

CMD ["python3", "-m", "apify_actor.src.main"]
