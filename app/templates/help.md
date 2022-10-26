```
https://tailwindui.com/components/preview
https://daisyui.com/components/
```

# Import dependencies
```
{% block before_head %}
  {{ super() }}
   {% import "helpers/src_macros.html" as macro %}
   {{ macro.filehelper(spinner=True) }}
{% endblock %}
```

# Hide when screen is smaller
```
<div class="hidden sm:block">
  <p>asdasd</p>
</div>
```

# Show when screen gets smaller
```
class="lg:hidden"
```

# Open modal on click
$(document).on('click', '.modal-button', function() {
  document.getElementById('agent-modal').checked = true;
});

# Fonts
bold - text-sm font-medium text-gray-500
regular - text-sm text-gray-900
hover - text-base font-medium text-gray-500 hover:text-gray-900

# Row
```
<div class="grid grid-rows-1 grid-flow-col gap-4">
</div>
```

# Hor line
```
<div class="hidden sm:block" aria-hidden="true">
  <div class="py-5">
    <div class="border-t border-gray-200"></div>
  </div>
</div>
```

# Creating rows with differing columns - https://tailwindcss.com/docs/grid-column
```
<div class="grid grid-cols-6 gap-4 mt-5">
  <div class="col-span-4">
    <div class="card bg-base-100">
      <div class="card-body">
        <h2 class="card-title">Card title!</h2>
        <p>If a dog chews shoes whose shoes does he choose?</p>
      </div>
    </div>
  </div>
  <div class="col-span-2">
    <div class="card bg-base-100">
      <div class="card-body">
        <h2 class="card-title">Card title!</h2>
        <p>If a dog chews shoes whose shoes does he choose?</p>
      </div>
    </div>
  </div>
</div>
```

# Card with transparent header
```
<div class="card bg-base-100">
      <div class="card-body">
        <h2 class="card-title">Card title!</h2>
        <p>If a dog chews shoes whose shoes does he choose?</p>
      </div>
    </div>
```

# Card with header
```
<div class="bg-white shadow overflow-hidden sm:rounded-lg">
  <div class="px-4 py-5 sm:px-6">
    <h3 class="text-lg leading-6 font-medium text-gray-900">Applicant Information</h3>
    <p class="mt-1 max-w-2xl text-sm text-gray-500">Personal details and application.</p>
  </div>
  <div class="border-t border-gray-200">
	<div class="bg-gray-50 px-4 py-5 sm:grid sm:px-6">
	  <p class="text-sm font-medium text-gray-500">body</p>
    </div>
  </div>
</div>
```

# Card with button
```
<div class="card w-96 bg-base-100 shadow-xl">
  <div class="card-body">
    <h2 class="card-title">Card title!</h2>
    <p>If a dog chews shoes whose shoes does he choose?</p>
    <div class="card-actions justify-end">
      <button class="btn btn-primary">Buy Now</button>
    </div>
  </div>
</div>
```
#(https://tailwindui.com/components/preview

# Open modal on click
```
$(document).on('click', '.modal-button', function() {
  document.getElementById('agent-modal').checked = true;
});
```

# Ajax
```
  $.ajax({
    type: "POST",
    url: url,
    data: JSON.stringify(data),
    contentType: "application/json; charset=utf-8",
    dataType: "json",
    success: function(data){
        return(data)
    },
    error: function(errMsg) {
        return(errMsg);
    }
  })
```
# Button with data ID (and click)
```
<button data-id="test" class="btn my-button">Click</button>
$(document).on('click', '.my-button', function() {
  var id = $(this).data('id')
  // set data-id
  $(".my-button").data("id","new value")
});
```

# Fonts
```
bold - text-sm font-medium text-gray-500
regular - text-sm text-gray-900
hover - text-base font-medium text-gray-500 hover:text-gray-900
```

# Flex box (center items)
```
<div class="flex flex-row justify-center">
<div>
  <h2 class="text-3xl font-bold tracking-tight text-gray-900 sm:text-4xl text-center">Header</h2>
</div>
<div>
  <img class="object-contain h-12 w-15" src="" alt="New">
</div>
</div>
<p class="mt-4 text-gray-500 text-center mb-10">Placeholder</p>
<div class="min-w-full flex flex-col items-center">
  <a href="" class="btn btn-accent text-white">Button</a>
</div>
```

# Responsive Card (with mult span)
```
<div class="grid grid-cols-1 sm:grid-cols-1 md:grid-cols-1 lg:grid-cols-4 lg:gap-2 gap-y-2">
  <div class="col-span-1">
    <div class="card bg-base-100">
      <div class="card-body">
        <h2 class="card-title">Coming soon</h2>
      </div>
    </div>
  </div>
  <div class="col-span-2">
    <div class="card bg-base-100">
      <div class="card-body">
        <h2 class="card-title">Coming soon</h2>
      </div>
    </div>
  </div>
  <div class="col-span-1">
    <div class="card bg-base-100">
      <div class="card-body">
        <h2 class="card-title">Coming soon</h2>
      </div>
    </div>
  </div>
</div>
```

# Responsive Card (3 col)
```
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
    <div class="card card-side bg-base-100 shadow-xl">
      <figure class="p-2"><img style="height:50px;width:50px" src="" alt="New"></figure>
      <div class="card-body p-4">
        <h2 class="card-title">Title</h2>
        <p class="text-sm font-medium text-gray-500">paragraph</p>
      </div>
    </div>
    <div class="card card-side bg-base-100 shadow-xl">
      <figure class="p-2"><img style="height:50px;width:50px" src="" alt="New"></figure>
      <div class="card-body p-4">
        <h2 class="card-title">Title</h2>
        <p class="text-sm font-medium text-gray-500">paragraph</p>
      </div>
    </div>
    <div class="card card-side bg-base-100 shadow-xl">
      <figure class="p-2"><img style="height:50px;width:50px" src="" alt="New"></figure>
      <div class="card-body p-4">
        <h2 class="card-title">Title</h2>
        <p class="text-sm font-medium text-gray-500">paragraph</p>
      </div>
    </div>
  </div>
```

