// Collect all the anchor elements with href attributes on the page
var links = Array.from(document.querySelectorAll("a[href]"));

// Array for known excluded values
var excludedValues = ['javascript:void(0)', 'javascript:void(0);', 'javascript:;'];

// Highlight all links on webpage
links.forEach(link => {
    if (!excludedValues.includes(link.href)) {
      link.style.backgroundColor = "yellow";
      link.style.color = "black";
      link.style.fontWeight = "bold";
      
    }
  });
  

// Extract the href values from the links and store them in the array
var hrefs = links
.map(link => link.href) 
.filter(href => !excludedValues.includes(href));

// Return hrefs array to extension
hrefs;

