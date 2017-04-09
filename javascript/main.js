$(document).ready(function(){
    
   /* action is initiated when user clicks either like or dislike */
   $('.fire').click(function(e){ 
        e.preventDefault();
        var method = $(this).data("action");
        var form = $('<form>').attr("method", "POST");
        var input = $("<input>").attr("type", "hidden").attr("name", "action").val(method);
        $(form).append($(input));
        $(form).submit();
    }); 
    
    /* action is initiated when user clicks edit for comments */ 
    $('.edit').click(function(e){ 
        e.preventDefault();
        var method = $(this).data("method");
        var form = $('<form>').attr("method", "POST");
        var input = $("<input>").attr("type", "hidden").attr("name", "action").val("edit");
        var inputComment = $("<input>").attr("type", "hidden").attr("name", "commentEdit").val(method);
        $(form).append($(input));
        $(form).append($(inputComment));                                           
        $(form).submit();
        });
    
    /* when browser loads, scrolls to comment field when user clicks edit for comments */
    $("html,body").animate({scrollTop:$(".comment-edit-tx").offset().top},1500); 
    
    /* action is initiated when user clicks delete for comments */
    $('.delete').click(function(e){ 
        e.preventDefault();
        var method = $(this).data("method");
        var form = $('<form>').attr("method", "POST");
        var input = $("<input>").attr("type", "hidden").attr("name", "action").val("delete");
        var inputComment = $("<input>").attr("type", "hidden").attr("name", "commentDelete").val(method);
        $(form).append($(input));
        $(form).append($(inputComment));                                           
        $(form).submit();
        });  
});