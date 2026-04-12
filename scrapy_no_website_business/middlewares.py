from scrapy import signals


class SpiderLifecycleMiddleware:
    @classmethod
    def from_crawler(cls, crawler):
        middleware = cls()
        crawler.signals.connect(middleware.spider_opened, signal=signals.spider_opened)
        return middleware

    def spider_opened(self, spider):
        spider.logger.info("Spider started: %s", spider.name)
