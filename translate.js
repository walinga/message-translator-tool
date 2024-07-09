// const url = "https://https://walinga.github.io/?url=www.messagehub.info/en/read.do?ref_num=56-0527"
// fetch(url)
//    .then( r => console.log(r) );

// https://www.messagehub.info/en/read.do?ref_num=56-0527

const o = "https://stackoverflow.com/questions/680562/can-javascript-read-the-source-of-any-web-pagehttps://stackoverflow.com/questions/680562/can-javascript-read-the-source-of-any-web-page";
const url = "?url=" + encodeURIComponent(o);
fetch(url)
   .then( r => {
        console.log(r);
        // r.json().then(j => console.log(j));
        r.text().then(t => console.log(t));
        r.fetch
    });

// TODO
// (1) Trigger lambda function
// (2) (Within lambda) Fetch content from messagehub.info website (English and Spanish)
//   - Probably need to fetch server-side due to CORS
//   - Idea: Use AWS lambda + Python
// (3) Compare pasted quote to message text. Find greatest common match
// (4) Display copyable quotes in each language
//   - Give credit to messagehub.info with a link to their website