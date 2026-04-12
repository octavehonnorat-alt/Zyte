import scrapy


class DirectoryBusinessItem(scrapy.Item):
    listing_url = scrapy.Field()
    source_url = scrapy.Field()
    name = scrapy.Field()
    address = scrapy.Field()
    phone = scrapy.Field()
    website = scrapy.Field()
    emails = scrapy.Field()
    description = scrapy.Field()
