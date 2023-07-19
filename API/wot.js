const url = 'https://wot-web-risk-and-safe-browsing.p.rapidapi.com/targets?t=google.com';
const options = {
    method: 'GET',
    headers: {
        'X-RapidAPI-Key': '22bb9f51b4msh6eb0ea28289c763p1ae395jsnb57942c61b0a',
        'X-RapidAPI-Host': 'wot-web-risk-and-safe-browsing.p.rapidapi.com'
    }
};

async function fetchData() {
   
    const response = await fetch(url, options);
    const result = await response.json();

    if (result[0]) {
        const target = result[0].target;
        const status = result[0].safety.status;
        const reputation = result[0].safety.reputations;
        const confidence = result[0].safety.confidence;
        const csreputation = result[0].childSafety.reputations;
        const csconfidence = result[0].childSafety.confidence;
    
        //const categories = result[0].categories.map(category => category.name).join(', ');
    
        // Now you can work with the extracted data
        console.log(target);
        console.log(status);
        console.log(reputation);
        console.log(confidence);
        console.log(csreputation);
        console.log(csconfidence);
        //console.log(categories);
    }
}
// Call the async function
fetchData();