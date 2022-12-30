// print all environment variables that start with REG_

for (const key in process.env) {
    if(key.startsWith('REG_')) {
        console.log(`${key} = ${process.env[key]}`)
    } else {
        continue;
    }
}
