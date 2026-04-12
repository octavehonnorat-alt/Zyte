BOT_NAME = "scrapy_no_website_business"

SPIDER_MODULES = ["scrapy_no_website_business.spiders"]
NEWSPIDER_MODULE = "scrapy_no_website_business.spiders"

ROBOTSTXT_OBEY = True

CONCURRENT_REQUESTS = 16
CONCURRENT_REQUESTS_PER_DOMAIN = 8
DOWNLOAD_DELAY = 0.5
RANDOMIZE_DOWNLOAD_DELAY = True
RETRY_ENABLED = True
RETRY_TIMES = 3
RETRY_HTTP_CODES = [429, 500, 502, 503, 504, 522, 524, 408]
DOWNLOAD_TIMEOUT = 20
COOKIES_ENABLED = False
TELNETCONSOLE_ENABLED = False

AUTOTHROTTLE_ENABLED = True
AUTOTHROTTLE_START_DELAY = 0.5
AUTOTHROTTLE_MAX_DELAY = 30
AUTOTHROTTLE_TARGET_CONCURRENCY = 2.0
AUTOTHROTTLE_DEBUG = False

HTTPCACHE_ENABLED = False

DEFAULT_REQUEST_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
}

SPIDER_MIDDLEWARES = {
    "scrapy_no_website_business.middlewares.SpiderLifecycleMiddleware": 543,
}

FEED_EXPORT_ENCODING = "utf-8"
