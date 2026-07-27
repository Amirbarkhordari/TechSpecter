"""HTTP resource fetching module."""

from techspecter.downloader.html_downloader import HtmlDocument, HtmlDownloader
from techspecter.downloader.http_client import AsyncHttpClient, HttpClientConfig
from techspecter.downloader.js_downloader import JsDownloadConfig, JsDownloader

__all__ = [
    "AsyncHttpClient",
    "HtmlDocument",
    "HtmlDownloader",
    "HttpClientConfig",
    "JsDownloadConfig",
    "JsDownloader",
]
