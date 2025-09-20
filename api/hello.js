module.exports=(req,res)=>{res.status(200).json({ok:true,route:"hello",time:new Date().toISOString()});};
