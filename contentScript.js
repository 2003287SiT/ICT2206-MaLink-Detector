// Collect all the anchor elements with href attributes on the page
var links = Array.from(document.querySelectorAll("a[href]"));

// Array for known excluded values
var excludedValues = ['javascript:void(0)', 'javascript:void(0);'];
// Extract the href values from the links and store them in the array
var hrefs = links
.map(link => link.href)
.filter(href => !excludedValues.includes(href));

// Return hrefs array to extension
hrefs;

