static time_t
timegm (struct tm *tm) {
	time_t ret;
	char *tz;
	
	tz = getenv("TZ");
	putenv("TZ=");
	tzset();
	ret = mktime(tm);
	if (tz) {
		char buf[256];
		snprintf(buf, sizeof(buf), "TZ=%s", tz);
		putenv(tz);
	}
	else
		putenv("TZ");
	tzset();
	return ret;
}
