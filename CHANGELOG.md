# 0.9.3

- Implement new interaction mode "dialog" to display device code/url
  with java AWT dialog
- Add JDBC parameter `oauth2InteractionMode`; retire/merge with
  `oauth2NoBrowser`
- When using `browser` interaction mode, open web server on
  random port bound to localhost, not 0.0.0.0
- Change `oauth2Audience` to non-required parameter
- Fix an URL parsing issue when URI does not contain //

# 0.9.2

- Initial Release
